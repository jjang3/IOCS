#!/bin/bash
# Runtime check for tiny after scripts/iocs run tiny: serve files with and without table.so.
# TARGET_DIR (set by scripts/run.sh) is result/tiny inside the container.
exec env TINY_DIR="${TARGET_DIR:-/iocs/result/tiny}" bash "$(dirname "$0")/../tests/serve_tiny.sh"
