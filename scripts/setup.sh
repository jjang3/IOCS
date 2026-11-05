#!/bin/bash
# One-time setup. Safe to re-run: every step is skipped when already done.
#   cp config.env.example config.env   # set BN_LINUX_ZIP (and BN_LICENSE if not in the default place)
#   scripts/setup.sh
# 1. submodules (third_party/libdft64, third_party/SUTURE)
# 2. macOS: check Homebrew tools, create the two colima VMs
# 3. build the images (scripts/build_images.sh) and copy them to the run VM
# 4. smoke test: PIN, SUTURE's clang/opt, a headless Binary Ninja load, FSGSBASE on the run VM
. "$(dirname "$0")/lib.sh"
say "submodules"
git -C "$IOCS_HOME" submodule update --init third_party/libdft64 third_party/SUTURE
for pair in "libdft64 $LIBDFT64_SHA" "SUTURE $SUTURE_SHA"; do
    set -- $pair; got=$(git -C "$IOCS_HOME/third_party/$1" rev-parse HEAD)
    [ "$got" = "$2" ] || die "third_party/$1 is at $got, versions.env says $2"
done
if [ "$IOCS_HOST" = mac ]; then
    for c in colima docker qemu-img limactl; do
        command -v $c >/dev/null || die "missing $c: brew install colima docker docker-buildx qemu lima-additional-guestagents"
    done
    ls "$(brew --prefix 2>/dev/null)"/share/lima/lima-guestagent.Linux-x86_64* >/dev/null 2>&1 \
        || die "x86_64 guest agent missing: brew install lima-additional-guestagents"
    for p in "$BUILD_PROFILE" "$RUN_PROFILE"; do
        [ -n "$(profile_status "$p")" ] && continue
        say "creating colima profile $p"
        if [ "$p" = "$BUILD_PROFILE" ]; then use_vm build; else use_vm run; fi
    done
fi
docker buildx version >/dev/null 2>&1 || die "docker buildx missing (needed for --build-context): macOS: brew install docker-buildx, then
  mkdir -p ~/.docker/cli-plugins && ln -sfn \$(brew --prefix)/opt/docker-buildx/bin/docker-buildx ~/.docker/cli-plugins/docker-buildx
  Linux: install docker-buildx-plugin"
[ -n "${BN_LICENSE:-}" ] && [ -f "$BN_LICENSE" ] || die "Binary Ninja licence not found; set BN_LICENSE in config.env"
"$IOCS_HOME/scripts/build_images.sh"
say "smoke test (build VM)"
use_vm build
in_image iocs:dev bash -c 'set -eo pipefail
  $PIN_ROOT/pin -version | head -1
  $SUTURE_CLANG --version | head -1
  opt --version | sed -n 2p
  test -f $SUTURE_HOME/llvm_analysis/MainAnalysisPasses/build_dir/SoundyAliasAnalysis/libSoundyAliasAnalysis.so && echo "SUTURE pass: ok"
  python3 - <<PY 2>&1 | grep -v Deprecat
import sys, binaryninja as b
v = b.BinaryViewType.get_view_of_file("/opt/pin-3.27/intel64/bin/pinbin")
syn = b.Settings().get_string("arch.x86.disassembly.syntax")
print("Binary Ninja", b.core_version(), "headless load:", v is not None, "syntax:", syn)
sys.exit(0 if v is not None and syn == "AT&T" else 1)
PY' || die "build-VM smoke test failed (above)"
say "smoke test (run VM): FSGSBASE and ptrace"
use_vm run
in_image iocs:dev bash -c 'grep -qw fsgsbase /proc/cpuinfo || { echo "FSGSBASE: missing (rewritten binaries would SIGILL)"; exit 1; }; echo "FSGSBASE: yes"
  p=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0); echo "ptrace_scope: $p"; [ "$p" = 0 ]' \
  || die "run-VM smoke test failed (above)"
say "setup done. Next: scripts/run.sh tiny    and    scripts/run_nginx.sh"
