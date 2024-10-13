# Use a base image (Ubuntu latest version)
FROM ubuntu:18.04

# Add the universe repository for missing packages
RUN apt-get -y update && \
    apt-get -y install software-properties-common && \
    add-apt-repository universe && \
    apt-get -y update

# Install prerequisites for adding repositories, build tools, and other dependencies
RUN apt-get -y update && apt-get -y install \
    software-properties-common \
    libpcre3-dev \
    libgeoip-dev \
    libssl-dev \
    make \
    gcc-4.8 \
    git \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libncurses5-dev \
    texinfo \
    autoconf \
    automake \
    bison \
    gettext \
    gperf \
    gzip \
    help2man \
    m4 \
    perl \
    tar \
    wget \
    xz-utils \
    python3-tk \
    emacs \
    zsh \
    fonts-powerline \
    autopoint && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for common paths
ENV USER_HOME=/root \
    IBCS_HOME=/root/IBCS \
    COREUTILS_HOME=/root/coreutils \ 
    NGINX_HOME=/root/nginx \
    BINARYNINJA_PATH=/root/binaryninja/python

# Update PYTHONPATH to include Binary Ninja (initialize if undefined)
ENV PYTHONPATH="/root/binaryninja/python:${PYTHONPATH}"

# Clone the coreutils repository into the working directory
RUN git clone git://git.sv.gnu.org/coreutils $COREUTILS_HOME

# Check if the build directory exists; if not, create it and run the build process
RUN if [ ! -d $COREUTILS_HOME/build ]; then \
        mkdir -p $COREUTILS_HOME/build && \
        cd $COREUTILS_HOME && \
        ./bootstrap && \
        FORCE_UNSAFE_CONFIGURE=1 CC=gcc CFLAGS="-O3 -gdwarf-2 -save-temps=obj -Wno-error -fno-omit-frame-pointer -fno-asynchronous-unwind-tables -fno-exceptions" \
        ./configure --prefix=$COREUTILS_HOME/build && \
        make -j$(nproc) && \
        make install; \
    else \
        echo "Build directory already exists, skipping build."; \
    fi

# Set the working directory to root
WORKDIR /root/

# Download and unpack NGINX version 1.3.9
RUN wget http://nginx.org/download/nginx-1.3.9.tar.gz \
    && tar -xvf nginx-1.3.9.tar.gz

# Check if the NGINX build directory exists; if not, create it and run the build process
RUN cd nginx-1.3.9 && \
    if [ ! -d "${NGINX_HOME}/build" ]; then \
        ./configure --prefix="${NGINX_HOME}/build" \
        --with-cc-opt="-O3 -g -gdwarf-2 -save-temps=obj -fno-omit-frame-pointer -gno-variable-location-views" && \
        make -j$(nproc) && \
        make install; \
    else \
        echo "Build directory already exists, skipping build."; \
    fi

# Copy the requirements.txt file first to utilize cache for pip install if requirements.txt doesn't change
COPY ./requirements.txt /root/IBCS/requirements.txt

# Install dependencies in a virtual environment
RUN python3 -m venv /root/venv && \
    . /root/venv/bin/activate && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r /root/IBCS/requirements.txt

# Install oh-my-zsh and set zsh as the default shell
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended && \
chsh -s $(which zsh) && \
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting && \
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions && \
sed -i 's/plugins=(git)/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/' ~/.zshrc && \
echo "ZSH_THEME=\"agnoster\"" >> ~/.zshrc

# Copy the rest of the application files. This step is placed after the pip install to avoid caching issues
# when source code changes. If only code changes, this will invalidate the cache for this layer alone.
# At the beginning of your Dockerfile
ARG CACHEBUST=1
COPY ./ /root/IBCS/

# Set the working directory to IBCS
WORKDIR /root/IBCS


# Set the entrypoint or command
CMD ["zsh"]