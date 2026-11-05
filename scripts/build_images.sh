#!/bin/bash
# Build the three images on the build VM (macOS) or the local daemon (Linux).
#   scripts/build_images.sh            build what is missing or out of date
#   scripts/build_images.sh --force    rebuild all three
#   scripts/build_images.sh --mark     record the current inputs as built (no build; use only if the
#                                      images were just built from this checkout by other means)
# Needs BN_LINUX_ZIP (config.env): Binary Ninja 3.1.3469 for Linux, BinaryNinjaLinux.zip.
#   iocs-suture:llvm9        docker/suture.Dockerfile      LLVM 9 + SUTURE (third_party/SUTURE); ~25 min
#   iocs:dev                 docker/Dockerfile             pipeline toolchain (PIN, SUTURE, Binary Ninja)
#   iocs-nginx-build:20.04   docker/nginx-build.Dockerfile Nginx 1.3.9 build/runtime (glibc 2.31)
# "Out of date": the image's input stamp (Dockerfile, versions.env, the third_party scripts and the
# SUTURE submodule commit) differs from the one recorded when it was built. Rebuilding the SUTURE
# image always rebuilds iocs:dev, which copies from it.
. "$(dirname "$0")/lib.sh"
mode=${1:-}
need_cmd docker "install Docker (macOS: brew install colima docker docker-buildx)"
docker buildx version >/dev/null 2>&1 || die "docker buildx missing (needed for --build-context); see scripts/setup.sh"
[ -f "$IOCS_HOME/third_party/SUTURE/run_nohup.sh" ] || die "third_party/SUTURE is empty: git submodule update --init third_party/SUTURE"
BN_LINUX_ZIP=${BN_LINUX_ZIP:-}
[ -f "$BN_LINUX_ZIP" ] || die "set BN_LINUX_ZIP in config.env to your BinaryNinjaLinux.zip (Binary Ninja $BINARYNINJA_VERSION)"
use_vm build
mkdir -p "$IMAGE_CACHE"
stamp() {  # <dockerfile> -> hash of everything that image is built from
    { cat "$IOCS_HOME/docker/$1" "$IOCS_HOME/third_party/versions.env" "$IOCS_HOME/.dockerignore"
      case $1 in
        suture.Dockerfile) cat "$IOCS_HOME/third_party/build_suture.sh"; git -C "$IOCS_HOME/third_party/SUTURE" rev-parse HEAD ;;
        Dockerfile) cat "$IOCS_HOME/third_party/get_pin.sh" "$IOCS_HOME/docker/binaryninja-settings.json"; shasum -a 256 < "$BN_LINUX_ZIP" ;;
      esac; } | shasum -a 256 | cut -c1-16
}
stampfile() { echo "$IMAGE_CACHE/$(echo "$1" | tr ':/' '__').stamp"; }
rebuilt_suture=0
b() { local tag=$1 file=$2; shift 2; local s; s=$(stamp "$file")
      if [ "$mode" = --mark ]; then docker image inspect "$tag" >/dev/null 2>&1 && echo "$s" > "$(stampfile "$tag")"; say "$tag marked $s"; return; fi
      if [ "$mode" != --force ] && docker image inspect "$tag" >/dev/null 2>&1 \
         && [ "$s" = "$(cat "$(stampfile "$tag")" 2>/dev/null)" ] && ! { [ "$tag" = iocs:dev ] && [ $rebuilt_suture = 1 ]; }; then
          say "$tag up to date ($s)"; return
      fi
      say "building $tag ($file, inputs $s)"
      docker build --platform linux/amd64 -f "$IOCS_HOME/docker/$file" "$@" -t "$tag" "$IOCS_HOME"
      echo "$s" > "$(stampfile "$tag")"
      [ "$tag" = iocs-suture:llvm9 ] && rebuilt_suture=1 || true; }
# The Dockerfile reads /bn/BinaryNinjaLinux.zip: stage exactly that file as the "bn" context.
bn_ctx=$(mktemp -d); trap 'rm -rf "$bn_ctx"' EXIT
cp "$BN_LINUX_ZIP" "$bn_ctx/BinaryNinjaLinux.zip"
b iocs-suture:llvm9 suture.Dockerfile
b iocs:dev Dockerfile --build-context bn="$bn_ctx" \
    --build-arg PYELFTOOLS_VERSION="$PYELFTOOLS_VERSION" --build-arg TERMCOLOR_VERSION="$TERMCOLOR_VERSION"
b iocs-nginx-build:20.04 nginx-build.Dockerfile
[ "$mode" = --mark ] || save_images
say "images ready on $DOCKER_CONTEXT"
