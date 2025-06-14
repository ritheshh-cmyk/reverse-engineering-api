# Use Debian Bookworm as base image
FROM debian:bookworm-slim

# Set working directory
WORKDIR /app

# Prevent system services from starting
ENV DEBIAN_FRONTEND=noninteractive
ENV INITRD=No
ENV RUNLEVEL=1

# Create a policy file to prevent service starts
RUN echo '#!/bin/sh\nexit 101' > /usr/sbin/policy-rc.d && \
    chmod +x /usr/sbin/policy-rc.d

# Add Debian repositories
RUN echo "deb http://deb.debian.org/debian bookworm main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian-security bookworm-security main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian bookworm-updates main contrib non-free" >> /etc/apt/sources.list

# Batch 1: Core build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    cmake \
    binwalk \
    gdb \
    strace \
    ltrace \
    valgrind \
    tcpdump \
    netcat-openbsd \
    nmap \
    file \
    && rm -rf /var/lib/apt/lists/*

# Batch 2: System utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    procps \
    p7zip-full \
    unzip \
    curl \
    wget \
    libcapstone-dev \
    libunicorn-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Batch 3: Analysis libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcap-dev \
    binutils \
    libmagic1 \
    libmagic-dev \
    libyara-dev \
    libfrida-dev \
    libradare2-dev \
    libz3-dev \
    libkeystone-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt .

# Batch 4: Core Python packages
RUN pip3 install --no-cache-dir \
    flask==2.3.3 \
    flask-cors==4.0.0 \
    python-multipart==0.0.6 \
    gunicorn==21.2.0 \
    Werkzeug==2.3.7 \
    click==8.1.7 \
    itsdangerous==2.1.2 \
    Jinja2==3.1.2 \
    MarkupSafe==2.1.3 \
    keystone-engine==0.9.2 \
    unicorn==2.0.1 \
    scapy==2.5.0 \
    requests==2.31.0 \
    pycryptodome==3.19.0 \
    cryptography==41.0.3

# Batch 5: Analysis Python packages
RUN pip3 install --no-cache-dir \
    python-magic==0.4.27 \
    olefile==0.46 \
    tqdm==4.66.1 \
    colorama==0.4.6 \
    pygments==2.16.1 \
    rich==13.5.2 \
    angr==9.2.86

# Install additional tools from source
RUN cd /tmp && \
    git clone https://github.com/radareorg/radare2 && \
    cd radare2 && \
    ./sys/install.sh && \
    cd .. && \
    rm -rf radare2 && \
    wget https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-amd64_linux.tar.xz && \
    tar xf upx-4.2.1-amd64_linux.tar.xz && \
    mv upx-4.2.1-amd64_linux/upx /usr/local/bin/ && \
    rm -rf upx-4.2.1-amd64_linux*

# Copy the application
COPY backend/ .

# Set Python path
ENV PYTHONPATH=/app
ENV PORT=8000

# Expose the port the app runs on
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Command to run the application with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "120", "app:app"]
