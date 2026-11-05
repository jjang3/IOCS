#!/bin/bash
# Fetch Intel PIN into <dest> (default third_party/pin) and verify its SHA-256.
#   third_party/get_pin.sh [dest]          -> <dest>/pin-3.27/pin
# A cached tarball in $IOCS_DOWNLOAD_CACHE (default ~/.cache/iocs-downloads) is reused.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); . "$here/versions.env"
dest=${1:-$here/pin}; cache=${IOCS_DOWNLOAD_CACHE:-$HOME/.cache/iocs-downloads}
mkdir -p "$dest" "$cache"
tgz=$cache/$PIN_NAME.tar.gz
[ -f "$tgz" ] || curl -fsSL -o "$tgz.part" "$PIN_URL" && { [ -f "$tgz" ] || mv "$tgz.part" "$tgz"; }
echo "$PIN_SHA256  $tgz" | sha256sum -c - 2>/dev/null || echo "$PIN_SHA256  $tgz" | shasum -a 256 -c -
if [ ! -x "$dest/pin-3.27/pin" ]; then
    tar -xzf "$tgz" -C "$dest" && mv "$dest/$PIN_NAME" "$dest/pin-3.27"
fi
"$dest/pin-3.27/pin" -version 2>/dev/null | head -1 || echo "PIN unpacked at $dest/pin-3.27 (runs on x86-64 Linux only)"
