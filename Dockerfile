# Use Python 3.10 slim as base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Prevent system services from starting
ENV DEBIAN_FRONTEND=noninteractive
ENV INITRD=No
ENV RUNLEVEL=1

# Create a policy file to prevent service starts
RUN echo '#!/bin/sh\nexit 101' > /usr/sbin/policy-rc.d && \
    chmod +x /usr/sbin/policy-rc.d

# Install core dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install analysis tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    binwalk \
    gdb \
    strace \
    ltrace \
    valgrind \
    tcpdump \
    netcat-openbsd \
    nmap \
    file \
    procps \
    p7zip-full \
    unzip \
    curl \
    wget \
    git \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install development libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
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
