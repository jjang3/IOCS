#!/bin/bash
# Shared helpers for scripts/*.sh. Source it; do not run it.
#
# Two host kinds:
#   mac   - macOS arm64 with colima. Two VMs, one running at a time:
#             build VM (iocs-rosetta): aarch64 + Rosetta, fast amd64 for compiling/patching,
#                                       but no ptrace (PIN) and no FSGSBASE (rdgsbase SIGILLs);
#             run VM   (iocs-x86):     QEMU x86_64, slow, but PIN and rewritten binaries work.
#   linux - native x86-64 Linux: one docker context does everything.
# use_vm build|run switches to the right one; images are built on the build VM and copied to
# the run VM's image store (each colima profile has its own) when they differ.
set -euo pipefail

IOCS_HOME=${IOCS_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
# shellcheck disable=SC1091
. "$IOCS_HOME/third_party/versions.env"
[ -f "$IOCS_HOME/config.env" ] && . "$IOCS_HOME/config.env"

case "$(uname -s)" in Darwin) IOCS_HOST=${IOCS_HOST:-mac} ;; *) IOCS_HOST=${IOCS_HOST:-linux} ;; esac
BUILD_PROFILE=${BUILD_PROFILE:-iocs-rosetta}
RUN_PROFILE=${RUN_PROFILE:-iocs-x86}
BUILD_PROFILE_ARGS=${BUILD_PROFILE_ARGS:-"--arch aarch64 --vm-type vz --vz-rosetta --cpu 8 --memory 14 --disk 80"}
RUN_PROFILE_ARGS=${RUN_PROFILE_ARGS:-"--arch x86_64 --vm-type qemu --cpu 4 --memory 8 --disk 60"}
IMAGE_CACHE=${IMAGE_CACHE:-$HOME/.cache/iocs-images}
IMAGES=(iocs:dev iocs-nginx-build:20.04)

# Binary Ninja licence: config.env BN_LICENSE, else the macOS default location.
if [ -z "${BN_LICENSE:-}" ]; then
    for f in "$HOME/Library/Application Support/Binary Ninja/license.dat" "$HOME/.binaryninja/license.dat"; do
        [ -f "$f" ] && { BN_LICENSE=$f; break; }
    done
fi

say()  { printf '\033[1;34m[iocs]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[iocs] error:\033[0m %s\n' "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1 ($2)"; }

profile_status() { colima list 2>/dev/null | awk -v p="$1" '$1==p {print $2}'; }

# use_vm build|run : make the matching docker daemon current (export DOCKER_CONTEXT).
use_vm() {
    local role=$1
    if [ "$IOCS_HOST" = linux ]; then
        export DOCKER_CONTEXT=${IOCS_DOCKER_CONTEXT:-default}
        if [ "$role" = run ] && [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" != 0 ]; then
            say "kernel.yama.ptrace_scope != 0; PIN needs: sudo sysctl -w kernel.yama.ptrace_scope=0"
        fi
        return
    fi
    local want other args
    if [ "$role" = build ]; then want=$BUILD_PROFILE; other=$RUN_PROFILE; args=$BUILD_PROFILE_ARGS
    else want=$RUN_PROFILE; other=$BUILD_PROFILE; args=$RUN_PROFILE_ARGS; fi
    if [ "$(profile_status "$want")" != Running ]; then
        if [ "$(profile_status "$other")" = Running ]; then
            # leaving the build VM: make sure the run VM will get its current images
            [ "$role" = run ] && DOCKER_CONTEXT=colima-$other save_images
            say "stopping $other"; colima stop --profile "$other" >/dev/null 2>&1
        fi
        mkdir -p "$IMAGE_CACHE"; local log=$IMAGE_CACHE/colima-$want.log
        say "starting $want (log: $log)"
        # shellcheck disable=SC2086
        colima start --profile "$want" $args > "$log" 2>&1 || { tail -20 "$log" >&2; die "colima start --profile $want failed (log: $log)"; }
    fi
    export DOCKER_CONTEXT=colima-$want
    if [ "$role" = run ]; then
        colima ssh --profile "$want" -- sudo sysctl -qw kernel.yama.ptrace_scope=0 >/dev/null
        sync_images
    fi
}

# Copy images saved from the build VM into the current daemon if missing or different.
sync_images() {
    local img f id
    for img in "${IMAGES[@]}"; do
        f=$IMAGE_CACHE/$(echo "$img" | tr ':/' '__')
        [ -f "$f.tar.gz" ] || continue
        id=$(docker image inspect --format '{{.Id}}' "$img" 2>/dev/null || true)
        if [ "$id" != "$(cat "$f.id" 2>/dev/null)" ]; then
            say "loading $img into $DOCKER_CONTEXT"; gunzip -c "$f.tar.gz" | docker load >/dev/null
        fi
    done
}

# Save images from the current (build) daemon so the run VM can load them.
save_images() {
    [ "$IOCS_HOST" = mac ] || return 0
    mkdir -p "$IMAGE_CACHE"; local img f id
    for img in "${IMAGES[@]}"; do
        f=$IMAGE_CACHE/$(echo "$img" | tr ':/' '__'); id=$(docker image inspect --format '{{.Id}}' "$img")
        if [ "$id" != "$(cat "$f.id" 2>/dev/null)" ]; then
            say "saving $img to $f.tar.gz"
            { docker save "$img" | gzip -1 > "$f.tar.gz.part" && mv "$f.tar.gz.part" "$f.tar.gz" && echo "$id" > "$f.id"; } \
                || { rm -f "$f.tar.gz.part" "$f.id"; die "saving $img to $f.tar.gz failed"; }
        fi
    done
}

# in_image <image> <command...> : run in a container with the repo at /iocs.
in_image() {
    local img=$1; shift
    # (never empty: macOS /bin/bash 3.2 treats an empty "${a[@]}" as unbound under set -u)
    local args=(--rm --platform linux/amd64 -v "$IOCS_HOME:/iocs" -w /iocs)
    if [ "$img" = iocs:dev ]; then
        [ -n "${BN_LICENSE:-}" ] && [ -f "$BN_LICENSE" ] || die "Binary Ninja licence not found; set BN_LICENSE in config.env"
        args+=(-v "$BN_LICENSE:/root/.binaryninja/license.dat:ro")
    fi
    local rc=0; docker run "${args[@]}" "$img" "$@" || rc=$?
    fix_owner
    return $rc
}

# Native Linux: containers run as root, so give the repo's run outputs back to the caller.
# (colima mounts already map ownership to the macOS user.)
fix_owner() {
    [ "$IOCS_HOST" = linux ] || return 0
    docker run --rm -v "$IOCS_HOME:/iocs" --entrypoint chown iocs-nginx-build:20.04 -R "$(id -u):$(id -g)" \
        /iocs/result /iocs/build /iocs/src/dta/lib /iocs/third_party/libdft64 >/dev/null 2>&1 || true
}

# Evidence: every scripted run leaves a plain-text record under evidence/<name>/<UTC stamp>/.
evidence_start() {
    EVID=$IOCS_HOME/evidence/$1/$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$EVID"
    {
        echo "run:        $1"
        echo "started:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "host:       $IOCS_HOST ($(uname -sm))"
        echo "repo:       $(git -C "$IOCS_HOME" rev-parse --short HEAD)$([ -z "$(git -C "$IOCS_HOME" status --porcelain --ignore-submodules=dirty -- . ':!evidence')" ] || echo ' (+uncommitted changes)')"
        git -C "$IOCS_HOME" submodule status third_party/ | sed 's/^/submodule: /'
        echo "versions:   PIN $PIN_NAME, SUTURE $SUTURE_SHA, LLVM $LLVM_MIRROR_LLVM_SHA, Binary Ninja $BINARYNINJA_VERSION"
    } > "$EVID/env.txt"
    say "evidence -> ${EVID#$IOCS_HOME/}"
}
ev_images() {  # record image IDs as seen by the current daemon
    local img; for img in "${IMAGES[@]}"; do echo "image:      $img $(docker image inspect --format '{{.Id}}' "$img" 2>/dev/null | cut -c1-19) on ${DOCKER_CONTEXT:-default}"; done >> "$EVID/env.txt"
}
# ev_run <log name> <command...> : run, keep an ANSI-stripped log, return the command's status.
ev_run() {
    local name=$1; shift; local rc
    say "$name"
    { echo "\$ $*"; local r=0; "$@" 2>&1 || r=$?; echo "$r" > "$EVID/.$name.rc"; printf '\n[exit %d]\n' "$r"; } \
        | sed -e 's/\x1b\[[0-9;]*m//g' > "$EVID/$name.log"
    rc=$(cat "$EVID/.$name.rc" 2>/dev/null || echo 1); rm -f "$EVID/.$name.rc"
    [ "$rc" -eq 0 ] || { tail -15 "$EVID/$name.log" >&2; return "$rc"; }
}
ev_summary() { echo "$*" | tee -a "$EVID/summary.txt" >&2; }
# ev_sites <dir> <out> : every rewritten access site, one per line:
#   <file>:<line>: <macro call>    <- <the line before it>
# In src/rewriter the line before a *_gs macro is the original instruction,
# kept with an extra tab as the shadow copy (stores) or replaced (loads); both are shown as-is.
ev_sites() {
    ( cd "$1" && find . -name '*.s' | sort | while read -r f; do
        awk -v f="${f#./}" '/^[[:space:]]+[a-z_]+_gs[[:space:]]/ { gsub(/[[:space:]]+/, " ", $0); g=prev; gsub(/[[:space:]]+/, " ", g)
                             printf "%s:%d:%s    <-%s\n", f, NR, $0, g } { prev=$0 }' "$f"
      done ) > "$2"
}
# ev_finalize : logs over 1 MB are kept complete but xz-compressed (read with xzcat) so the
# record stays small enough for git; everything else stays plain text.
ev_finalize() {
    local f; for f in "$EVID"/*.log; do
        [ "$(wc -c < "$f")" -gt 1048576 ] || continue
        if command -v xz >/dev/null; then xz -9 -f "$f"; else gzip -9 -f "$f"; fi
    done
    ls -1 "$EVID" > "$EVID/.files"; mv "$EVID/.files" "$EVID/files.txt"
}
