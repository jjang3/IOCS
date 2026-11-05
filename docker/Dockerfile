# IOCS toolchain image (linux/amd64). The repository itself is bind-mounted at /iocs; the
# image carries only the tools the pipeline calls.
#
#   scripts/build_images.sh            (repository root as build context; see .dockerignore)
#   docker build --platform linux/amd64 -f docker/Dockerfile \
#     --build-context bn=<dir holding BinaryNinjaLinux.zip> -t iocs:dev .
#
#   docker run --rm -it --platform linux/amd64 -v "$PWD":/iocs \
#     -v <licence file>:/root/.binaryninja/license.dat:ro iocs:dev
#
# Binary Ninja is commercial. The zip comes from a local build context and the licence is
# mounted at run time, so neither is in this repository; never push an image built from it.
#
# Two daemons, two jobs (see NOTES.md):
#   - Rosetta-backed amd64 (colima --vz-rosetta) is fast for compiling, but has no FSGSBASE,
#     so rewritten binaries die with SIGILL there.
#   - QEMU x86_64 (colima --arch x86_64 --vm-type qemu) exposes FSGSBASE; run binaries there.
FROM iocs-suture:llvm9 AS suture

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
# Python 3.10 (the code needs >= 3.10 for match statements and < 3.13 for cgitb).
# zsh: benchmarks/Makefile and libMakefile use SHELL=/bin/zsh. gawk/grep -P: the .vuln extraction.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential gcc-9 g++-9 gcc-multilib g++-multilib clang make binutils file \
      zsh gawk grep curl wget ca-certificates git unzip xz-utils patch \
      python3 python3-pip python3-venv python3-tk python-is-python3 \
      libtinfo5 libxml2 zlib1g apache2-utils procps iproute2 libdbus-1-3 \
      libpcre3-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# The Makefiles rely on GCC < 11 -save-temps=obj naming; make gcc mean gcc-9.
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 \
      --slave /usr/bin/g++ g++ /usr/bin/g++-9 \
    && gcc --version | head -1

# Versions come from third_party/versions.env via scripts/build_images.sh (--build-arg).
ARG PYELFTOOLS_VERSION=0.29
ARG TERMCOLOR_VERSION=2.4.0
RUN pip3 install --no-cache-dir pyelftools==${PYELFTOOLS_VERSION} termcolor==${TERMCOLOR_VERSION}

# Intel PIN, fetched and checksummed by third_party/get_pin.sh (version in third_party/versions.env).
COPY third_party/versions.env third_party/get_pin.sh /opt/iocs-third_party/
RUN /opt/iocs-third_party/get_pin.sh /opt && rm -rf /root/.cache/iocs-downloads
ENV PIN_ROOT=/opt/pin-3.27

# SUTURE + its LLVM 9 (built in docker/suture.Dockerfile). Only what the pipeline runs.
COPY --from=suture /opt/suture /opt/suture
COPY --from=suture /opt/suture_deps/llvm/build/bin/clang-9 /opt/suture_deps/llvm/build/bin/opt \
     /opt/suture_deps/llvm/build/bin/llvm-dis /opt/suture_deps/llvm/build/bin/llvm-config \
     /opt/suture_deps/llvm/build/bin/
COPY --from=suture /opt/suture_deps/llvm/build/lib/clang /opt/suture_deps/llvm/build/lib/clang
RUN cd /opt/suture_deps/llvm/build/bin && ln -s clang-9 clang && ln -s clang-9 clang++ \
    && ./clang --version | head -1 && ./opt --version | sed -n 2p
ENV LLVM_ROOT=/opt/suture_deps/llvm/build \
    PATH=/opt/suture_deps/llvm/build/bin:$PATH \
    SUTURE_HOME=/opt/suture \
    SUTURE_CLANG=/opt/suture_deps/llvm/build/bin/clang \
    LD_LIBRARY_PATH=/opt/suture/llvm_analysis/MainAnalysisPasses/z3/bin

# Binary Ninja 3.1.3469 headless API from the local zip (build context "bn").
RUN --mount=type=bind,from=bn,target=/bn \
    unzip -q /bn/BinaryNinjaLinux.zip -d /opt && test -f /opt/binaryninja/python/binaryninja/__init__.py
ENV PYTHONPATH=/opt/binaryninja/python
# Every IOCS rewriter matches Binary Ninja's disassembly text against gcc's AT&T .s. The code
# asks for AT&T per load (options={"arch.x86.disassembly.syntax": "AT&T"}), but Binary Ninja
# 3.1 registers that setting only when the x86 plugin loads and ignores it per load: without
# this user-level setting it emits Intel syntax and nothing is ever patched.
COPY docker/binaryninja-settings.json /root/.binaryninja/settings.json

ENV IOCS_HOME=/iocs PYTHONHASHSEED=0
WORKDIR /iocs
CMD ["bash"]
