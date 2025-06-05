# --- Builder Stage ---
FROM python:3.10-slim AS builder

# Create sources.list if it doesn't exist
RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list

# Install essential system dependencies (add bison and flex for YARA build)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    pkg-config \
    autoconf \
    automake \
    libtool \
    wget \
    unzip \
    git \
    cmake \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# Install core libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    zlib1g-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libncurses5-dev \
    libncursesw5-dev \
    liblzma-dev \
    libgdbm-dev \
    libcapstone-dev \
    libunicorn-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Static Analysis Tools and clean up
RUN git clone https://github.com/radareorg/radare2.git /radare2 && \
    cd /radare2 && ./sys/install.sh --yes && \
    cd / && rm -rf /radare2

# Install Ghidra (headless)
COPY ghidra_11.3.2_PUBLIC_20250415.zip /ghidra.zip
RUN unzip /ghidra.zip -d /opt && \
    rm /ghidra.zip

# Install YARA and clean up
RUN git clone https://github.com/VirusTotal/yara.git /yara && \
    cd /yara && ./bootstrap.sh && ./configure && make && make install && \
    cd / && rm -rf /yara

# Install Python analysis libraries (core set)
RUN pip install --no-cache-dir \
    pefile \
    capstone \
    lief \
    pycryptodome \
    angr \
    triton \
    unicorn \
    keystone-engine \
    pwntools \
    ropgadget \
    radamsa \
    frida-tools \
    androguard \
    apktool \
    jadx \
    dex2jar \
    smali \
    baksmali \
    classy-shark && \
    rm -rf /root/.cache/pip

# Install UPX and clean up
RUN wget -q https://github.com/upx/upx/releases/download/v4.2.3/upx-4.2.3-amd64_linux.tar.xz && \
    tar -xf upx-4.2.3-amd64_linux.tar.xz && \
    mv upx-4.2.3-amd64_linux/upx /usr/local/bin/ && \
    rm -rf upx-4.2.3-amd64_linux*

# Install Android tools and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    apktool \
    androguard \
    dex2jar \
    jadx \
    smali \
    baksmali \
    && rm -rf /var/lib/apt/lists/*

# Install TrID and clean up
RUN wget -O /tmp/trid_linux.zip http://mark0.net/download/trid_linux.zip && \
    unzip /tmp/trid_linux.zip -d /tmp/trid && \
    mv /tmp/trid/trid /usr/local/bin/trid && \
    chmod +x /usr/local/bin/trid && \
    rm -rf /tmp/trid_linux.zip /tmp/trid

# Install dynamic analysis tools and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    valgrind \
    strace \
    ltrace \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Install network analysis tools and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    ngrep \
    tcpdump \
    wireshark-cli \
    && rm -rf /var/lib/apt/lists/*

# Install QEMU and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    qemu-user \
    && rm -rf /var/lib/apt/lists/*

# Remove build dependencies to save space
RUN apt-get purge -y --auto-remove \
    build-essential \
    python3-dev \
    pkg-config \
    autoconf \
    automake \
    libtool \
    git \
    cmake \
    bison \
    flex

# Set working directory
WORKDIR /app

# Copy backend folder and requirements
COPY backend /app/backend
COPY backend/requirements.txt /app/requirements.txt

# --- Final Stage ---
FROM python:3.10-slim

# Create sources.list if it doesn't exist
RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list

# Copy tools and app from builder
COPY --from=builder /usr/local/bin/upx /usr/local/bin/upx
COPY --from=builder /usr/local/bin/trid /usr/local/bin/trid
COPY --from=builder /opt/ghidra_11.3.2_PUBLIC /opt/ghidra_11.3.2_PUBLIC
COPY --from=builder /app /app

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/backend/requirements.txt && rm -rf /root/.cache/pip

# Install runtime dependencies and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    python3-setuptools python3-numpy python3-magic \
    mtd-utils gzip bzip2 tar arj p7zip-full cabextract cramfsswap squashfs-tools \
    gdb \
    strace \
    ltrace \
    tcpdump \
    wireshark-cli \
    qemu-system-x86 \
    qemu-user \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:${PATH}"
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_11.3.2_PUBLIC

EXPOSE 8000

CMD ["python", "-m", "backend.app"]
