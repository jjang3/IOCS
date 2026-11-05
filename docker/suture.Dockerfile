# SUTURE (static taint analysis) on LLVM 9, for the IOCS STA stage. Built by
# scripts/build_images.sh with the repository root as context:
#   docker build --platform linux/amd64 -f docker/suture.Dockerfile -t iocs-suture:llvm9 .
# The recipe is third_party/build_suture.sh (also usable on an x86-64 Linux host); versions are
# in third_party/versions.env; SUTURE's source is the submodule third_party/SUTURE.
# linux/amd64 only: SUTURE bundles an x86-64 z3. Compilation only, so a Rosetta daemon is fine.
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates python3 python-is-python3 \
      zlib1g-dev libtinfo-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*
COPY third_party/versions.env third_party/build_suture.sh /opt/iocs-third_party/
COPY third_party/SUTURE /opt/suture
RUN test -f /opt/suture/run_nohup.sh || { echo "third_party/SUTURE is empty: git submodule update --init third_party/SUTURE"; exit 1; } \
    && /opt/iocs-third_party/build_suture.sh /opt/suture /opt/suture_deps \
    && find /opt/suture_deps/llvm/build -name '*.o' -delete
ENV LLVM_ROOT=/opt/suture_deps/llvm/build PATH=/opt/suture_deps/llvm/build/bin:$PATH
WORKDIR /opt/suture
