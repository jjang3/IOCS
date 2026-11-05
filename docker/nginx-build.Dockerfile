# Compiler environment of record for the Nginx evaluation: Ubuntu 20.04, gcc 9.4, glibc 2.31.
# (The authors' committed test binaries say "GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0".)
# Nginx 1.3.9 does not build against glibc >= 2.32 (no <sys/sysctl.h>), so it is compiled and
# relinked here, and run here too (it links OpenSSL 1.1); the IOCS patcher runs in iocs:dev
# on the same bind-mounted tree. Run rewritten binaries only on a daemon with FSGSBASE.
#   docker build --platform linux/amd64 -f docker/nginx-build.Dockerfile -t iocs-nginx-build:20.04 .
#   (or scripts/build_images.sh)
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential binutils make zsh libpcre3-dev zlib1g-dev libssl-dev ca-certificates curl \
      apache2-utils procps \
    && rm -rf /var/lib/apt/lists/* && gcc --version | head -1
WORKDIR /iocs
