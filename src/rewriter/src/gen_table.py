import sys, getopt
import logging

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

from pprint import pprint

fun_table_offsets       = dict()

# Page sets of threads and signal handlers (table.c, after SLOT_COUNT and SLOT_SIZE(i)). A slot is
# a page per variable, not per activation, so two activations of a function that run at the same
# time must not share a page set. A new thread inherits its creator's gs base and a handler runs on
# the thread it interrupted: each thread gets a set of its own at pthread_create, and a handler (per
# nesting level) switches to a set of its own while it runs. table.so is preloaded, so these
# definitions interpose on the program's calls to libc and libpthread.
THREAD_SIGNAL_RUNTIME = r"""
#define IOCS_TLS __attribute__((tls_model("initial-exec")))
#define SIG_LEVELS 4
static __thread void **thread_table IOCS_TLS;          /* this thread's set (table on the main thread) */
static __thread void **sig_table[SIG_LEVELS] IOCS_TLS; /* a handler's set at each nesting level */
static __thread int sig_level IOCS_TLS;
static __thread void *outside_handlers IOCS_TLS;       /* the set the outermost handler interrupted */
static __thread int exit_rounds IOCS_TLS;

/* A page set like table, plus one entry that links free sets. System calls only: a handler maps
   its set the first time it runs */
static void **map_table(void)
{
    void **t = mmap(NULL, sizeof(void *) * (SLOT_COUNT + 1), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (t == MAP_FAILED)
        return NULL;
    for (int i = 0; i < SLOT_COUNT; ++i) {
        t[i] = mmap(NULL, SLOT_SIZE(i), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_32BIT | MAP_PRIVATE, -1, 0);
        if (t[i] == MAP_FAILED) {
            for (int j = 0; j < i; ++j)
                munmap(t[j], SLOT_SIZE(j));
            munmap(t, sizeof(void *) * (SLOT_COUNT + 1));
            return NULL;
        }
    }
    return t;
}

static void spin_lock(int *l) { while (__atomic_test_and_set(l, __ATOMIC_ACQUIRE)) sched_yield(); }
static void spin_unlock(int *l) { __atomic_clear(l, __ATOMIC_RELEASE); }

/* Sets of exited threads, reused by later ones so that a program that keeps creating threads
   does not keep mapping pages */
static void **free_tables;
static int free_lock;

static void **take_table(void)
{
    spin_lock(&free_lock);
    void **t = free_tables;
    if (t)
        free_tables = t[SLOT_COUNT];
    spin_unlock(&free_lock);
    return t ? t : map_table();
}

static void put_table(void **t)
{
    spin_lock(&free_lock);
    t[SLOT_COUNT] = free_tables;
    free_tables = t;
    spin_unlock(&free_lock);
}

static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int (*real_setspecific)(pthread_key_t, const void *);
static pthread_key_t exit_key;
static int exit_key_ok;

static void release_table(void *t)
{
    /* The thread's other TSD destructors may still run rewritten code: hold the set until
       glibc's last destructor round */
    if (++exit_rounds < PTHREAD_DESTRUCTOR_ITERATIONS) {
        real_setspecific(exit_key, t);
        return;
    }
    put_table(t);
    for (int i = 0; i < SIG_LEVELS; ++i)
        if (sig_table[i]) {
            put_table(sig_table[i]);
            sig_table[i] = NULL;
        }
}

/* libpthread is resolved when the program first creates a thread: a program without it never does */
static int threads_ready(void)
{
    static int ready, init_lock;
    if (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) == 0) {
        spin_lock(&init_lock);
        if (ready == 0) {
            int (*key_create)(pthread_key_t *, void (*)(void *)) = dlsym(RTLD_NEXT, "pthread_key_create");
            real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
            real_setspecific = dlsym(RTLD_NEXT, "pthread_setspecific");
            /* Without the key a thread's set is not reused after it exits */
            exit_key_ok = key_create && real_setspecific && key_create(&exit_key, release_table) == 0;
            __atomic_store_n(&ready, real_pthread_create ? 1 : -1, __ATOMIC_RELEASE);
        }
        spin_unlock(&init_lock);
    }
    return ready == 1;
}

struct thread_start { void *(*fn)(void *); void *arg; void **table; };

static void *thread_entry(void *p)
{
    struct thread_start s = *(struct thread_start *)p;
    free(p);
    thread_table = s.table;
    _writegsbase_u64((unsigned long long)s.table);
    if (exit_key_ok)
        real_setspecific(exit_key, s.table);
    return s.fn(s.arg);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*fn)(void *), void *arg)
{
    if (!threads_ready())
        return EAGAIN;
    struct thread_start *s = malloc(sizeof *s);
    void **t = s ? take_table() : NULL;
    if (!t) {
        free(s);
        return EAGAIN;
    }
    s->fn = fn;
    s->arg = arg;
    s->table = t;
    int rc = real_pthread_create(thread, attr, thread_entry, s);
    if (rc != 0) {
        put_table(t);
        free(s);
    }
    return rc;
}

/* The program's handler of each signal whose kernel handler is signal_entry */
static void *user_handler[NSIG];
static int user_siginfo[NSIG];
static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);
typedef sighandler_t (*signal_fn)(int, sighandler_t);
static signal_fn real_signal, real_bsd_signal, real_sysv_signal, real_sigset;
typedef void (*jump_fn)(struct __jmp_buf_tag *, int) __attribute__((__noreturn__));
static jump_fn real_longjmp, real__longjmp, real_siglongjmp, real_longjmp_chk;

/* Resolved by the constructor, not in a handler (dlsym is not async-signal-safe); here as well
   for a constructor of another library that runs first */
static void resolve_real(void)
{
    if (real_sigaction)
        return;
    real_signal = dlsym(RTLD_NEXT, "signal");
    real_bsd_signal = dlsym(RTLD_NEXT, "bsd_signal");
    real_sysv_signal = dlsym(RTLD_NEXT, "sysv_signal");
    real_sigset = dlsym(RTLD_NEXT, "sigset");
    real_longjmp = dlsym(RTLD_NEXT, "longjmp");
    real__longjmp = dlsym(RTLD_NEXT, "_longjmp");
    real_siglongjmp = dlsym(RTLD_NEXT, "siglongjmp");
    real_longjmp_chk = dlsym(RTLD_NEXT, "__longjmp_chk");
    __atomic_store_n(&real_sigaction, dlsym(RTLD_NEXT, "sigaction"), __ATOMIC_RELEASE);
}

static void signal_entry(int sig, siginfo_t *info, void *uc)
{
    void *interrupted = (void *)_readgsbase_u64();
    int level = sig_level++;
    if (level == 0)
        outside_handlers = interrupted;
    if (level >= SIG_LEVELS)
        level = SIG_LEVELS - 1;    /* deeper nesting shares the last level's set */
    if (!sig_table[level]) {
        int saved_errno = errno;
        sig_table[level] = map_table();
        errno = saved_errno;
    }
    if (sig_table[level])
        _writegsbase_u64((unsigned long long)sig_table[level]);
    void *fn = user_handler[sig];
    if (fn != (void *)SIG_DFL && fn != (void *)SIG_IGN) {
        if (user_siginfo[sig])
            ((void (*)(int, siginfo_t *, void *))fn)(sig, info, uc);
        else
            ((void (*)(int))fn)(sig);
    }
    _writegsbase_u64((unsigned long long)interrupted);
    sig_level--;
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
{
    resolve_real();
    if (sig <= 0 || sig >= NSIG)
        return real_sigaction(sig, act, old);
    void *prev = user_handler[sig];
    int prev_siginfo = user_siginfo[sig];
    struct sigaction mine;
    if (act && act->sa_handler != SIG_DFL && act->sa_handler != SIG_IGN) {
        mine = *act;
        user_siginfo[sig] = (act->sa_flags & SA_SIGINFO) != 0;
        user_handler[sig] = user_siginfo[sig] ? (void *)act->sa_sigaction : (void *)act->sa_handler;
        mine.sa_sigaction = signal_entry;
        mine.sa_flags |= SA_SIGINFO;
        act = &mine;
    }
    int rc = real_sigaction(sig, act, old);
    if (rc != 0) {
        user_handler[sig] = prev;
        user_siginfo[sig] = prev_siginfo;
    } else if (old && old->sa_sigaction == signal_entry) {
        /* The program sees its own handler (installed by sigaction or by signal) */
        if (prev_siginfo) {
            old->sa_sigaction = prev;
        } else {
            old->sa_flags &= ~SA_SIGINFO;
            old->sa_handler = prev;
        }
    }
    return rc;
}

/* signal and its variants: the variant installs signal_entry with its own semantics */
static sighandler_t wrap_signal(signal_fn real, int sig, sighandler_t handler)
{
    if (!real) {
        errno = ENOSYS;
        return SIG_ERR;
    }
    if (sig <= 0 || sig >= NSIG)
        return real(sig, handler);
    void *prev = user_handler[sig];
    int prev_siginfo = user_siginfo[sig];
    int runs = handler != SIG_DFL && handler != SIG_IGN && handler != SIG_ERR && handler != SIG_HOLD;
    if (runs) {
        user_handler[sig] = (void *)handler;
        user_siginfo[sig] = 0;
    }
    sighandler_t r = real(sig, runs ? (sighandler_t)signal_entry : handler);
    if (r == SIG_ERR) {
        user_handler[sig] = prev;
        user_siginfo[sig] = prev_siginfo;
    } else if (r == (sighandler_t)signal_entry) {
        r = (sighandler_t)prev;
    }
    return r;
}

sighandler_t signal(int sig, sighandler_t handler) { resolve_real(); return wrap_signal(real_signal, sig, handler); }
sighandler_t bsd_signal(int sig, sighandler_t handler) { resolve_real(); return wrap_signal(real_bsd_signal, sig, handler); }
sighandler_t sysv_signal(int sig, sighandler_t handler) { resolve_real(); return wrap_signal(real_sysv_signal, sig, handler); }
sighandler_t sigset(int sig, sighandler_t handler) { resolve_real(); return wrap_signal(real_sigset, sig, handler); }

/* A jump out of a handler (siglongjmp back to a main loop) skips the return of signal_entry that
   switches back: take the set the outermost handler interrupted. A jump within a handler is
   taken to leave it too. */
static void leave_handlers(void)
{
    if (sig_level > 0) {
        sig_level = 0;
        _writegsbase_u64((unsigned long long)outside_handlers);
    }
}

void longjmp(struct __jmp_buf_tag env[1], int val) { resolve_real(); leave_handlers(); real_longjmp(env, val); }
void _longjmp(struct __jmp_buf_tag env[1], int val) { resolve_real(); leave_handlers(); real__longjmp(env, val); }
void siglongjmp(struct __jmp_buf_tag env[1], int val) { resolve_real(); leave_handlers(); real_siglongjmp(env, val); }
void __longjmp_chk(struct __jmp_buf_tag env[1], int val) { resolve_real(); leave_handlers(); real_longjmp_chk(env, val); }
"""

def var_slots(var):
    """The stack slots (offset expressions) a variable is given: one for a scalar, pointer, array
    or union (a union's members share its storage), one per member for a struct object in the
    frame. A member that is a struct, union or array is one unit, like an array variable: an
    inner part is reached from the member's address, which a pointer to it passed to a callee
    also uses. A register or global variable, or a type without layout (void) gets none."""
    if var.offset_expr == None:
        return []
    if var.struct != None:
        return [member.offset_expr for member in var.struct.member_list if member.offset_expr != None]
    if var.kind in ("base", "enum", "pointer", "array", "union"):
        return [var.offset_expr]
    logger.error("Skipping: %s", var)
    return []

def generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir):
    # Offset to table offset set of the current working function
    offset_expr_to_table    = set()
    fun_slot_exprs          = set()
    table_offset = 0
    
    # Variable that is going to be patched
    off_var_count = 0
    # Variable count to patch
    var_patch = 9999
    # Function count to patch
    fun_patch = 0
    # print("Total variables to patch: ", count)
    # exit()
    for fun_idx,fun in enumerate(dwarf_fun_var_info):
        if True: 
        # if fun_idx == 0: # This is used to debug specific function
        # if fun == "parse_request":
            vars = dwarf_fun_var_info[fun]
            # print(fun)
            for var_idx, var in enumerate(vars):
                if True:
                    print(var)
                # if var_idx == 1: #Not work: 1,4,5
                #     print(var)
                    #     exit()
                    if var_idx < var_patch: #and var_idx != 5: # and var_idx == 6: # (and var_idx is used to debug)
                        for slot_expr in var_slots(var):
                            # Variables of disjoint scopes can share a stack slot (DWARF gives both
                            # the same offset), and so do bit-fields of one storage unit: one slot
                            if slot_expr in fun_slot_exprs:
                                continue
                            fun_slot_exprs.add(slot_expr)
                            logger.warning("Added")
                            offset_expr_to_table.add((slot_expr, table_offset))
                            table_offset += 8
                            off_var_count += 1
            fun_table_offsets[fun] = offset_expr_to_table.copy()
            offset_expr_to_table.clear()
            fun_slot_exprs.clear()
        
    
    # print("Total function: ", len(dwarf_fun_var_info))
    # print("Total variables getting patched: ", off_var_count)
    # varlist = list()
    logger.info("Generating the table with variable count: %d", off_var_count)
    if off_var_count % 2 != 0 and off_var_count != 1:
        # This is to avoid malloc(): corrupted top size error, malloc needs to happen in mod 2
        off_var_count += 1
    # ptr = "%p\n".strip()    printf("%s", addr_%d);
    include_lib_flags="""#define _GNU_SOURCE
#include <sys/auxv.h>
#include <elf.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
/* Will be eventually in asm/hwcap.h */
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE        (1 << 1)
#endif
#define PAGE_SIZE 4096
#define SLOT_COUNT %d
#define SLOT_SIZE(i) PAGE_SIZE
""" % (off_var_count)
    begin_table="""
void **table;
void __attribute__((constructor)) create_table()
{    
    table = malloc(sizeof(void*)*%d);\n
    if (!table) {
        perror("Failed to allocate memory for page table");
        exit(EXIT_FAILURE);
    }
    /*Pointer to shared memory region*/    
""" % (off_var_count) #(dwarf_var_count) #

    loop_table="""
    // Map each page
    for (int i = 0; i < %d; ++i) {
        table[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_32BIT | MAP_PRIVATE, -1, 0);
        if (table[i] == MAP_FAILED) {
            perror("Memory mapping failed");
            // Clean up previously mapped pages
            for (int j = 0; j < i; ++j) {
                munmap(table[j], PAGE_SIZE);
            }
            free(table);
            exit(EXIT_FAILURE);
        }
    }
""" % (off_var_count) # (dwarf_var_count) 
#     count = 0
#     while count <= dwarf_var_count: # May need to make this <= in order to avoid mod 2 bug
#         varentry = "\tvoid *addr_%d;" % count
#         mmapentry = """
#     addr_%d = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT, -1, 0);     
#     if (addr_%d == MAP_FAILED) {     
#         fprintf(stderr, "mmap() failed\\n");     
#         exit(EXIT_FAILURE);
#     }
#     table[%d] = addr_%d;\n
# """ % (count, count, count, count) #  | MAP_32BIT
#         varlist.append((varentry, mmapentry))
#         count += 1

    end_table="""\tthread_table = table;
\tresolve_real();
\t_writegsbase_u64((long long unsigned int)table);
}
void __attribute__((destructor)) cleanup_table() {
    // Unmap each page and free the table
    for (int i = 0; i < %d; ++i) {
        if (table[i]) {
            munmap(table[i], PAGE_SIZE);
        }
    }
    free(table);
}
""" % (off_var_count)# (dwarf_var_count) 
    table_file = open("%s/table.c" % target_dir, "w")
    table_file.write(include_lib_flags)
    table_file.write(THREAD_SIGNAL_RUNTIME)
    table_file.write(begin_table)
    table_file.write(loop_table)
    # for item in varlist:
    #     table_file.write(item[0])
    #     table_file.write(item[1])
    table_file.write(end_table)
    table_file.close()
    logger.info("Based on offsets, generate offsets per respective variables")
    return fun_table_offsets
    # pprint(dwarf_fun_var_info, width=1)