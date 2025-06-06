# Use Python 3.10 slim as base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gnupg2 \
    software-properties-common \
    && echo "deb http://deb.debian.org/debian bullseye main contrib non-free" >> /etc/apt/sources.list \
    && echo "deb http://deb.debian.org/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list \
    && echo "deb http://deb.debian.org/debian bullseye-updates main contrib non-free" >> /etc/apt/sources.list \
    && apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    python3-pip \
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

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt .

# Install Python dependencies in stages
RUN pip install --no-cache-dir -r requirements.txt || \
    (echo "Failed to install all packages, trying core packages first..." && \
     pip install --no-cache-dir flask==2.3.3 flask-cors==4.0.0 python-multipart==0.0.6 gunicorn==21.2.0 Werkzeug==2.3.7 click==8.1.7 itsdangerous==2.1.2 Jinja2==3.1.2 MarkupSafe==2.1.3 && \
     pip install --no-cache-dir -r requirements.txt)

# Copy the rest of the application
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
