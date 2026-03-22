ARG KERNEL_VERSION

#FROM --platform=linux/amd64 linuxkit/kernel:${KERNEL_VERSION} as ksrc
#FROM docker/for-desktop-kernel:5.10.25-6594e668feec68f102a58011bb42bd5dc07a7a9b as ksrc
#FROM --platform=linux/amd64 ubuntu:latest AS build
FROM linuxkit/kernel:6.6.13-44a5293614ca7c7674013e928cb11dcdbba73ba8 AS ksrc
FROM ubuntu:latest AS main

ARG BPFTRACE_VERSION
ARG PYTHON_VERSION

WORKDIR /kernel
COPY --from=ksrc /kernel-dev.tar .
RUN tar xf kernel-dev.tar

WORKDIR /workspace

RUN mv /kernel/usr/src/linux-headers* /kernel/usr/src/linux-headers

ARG DEBIAN_FRONTEND=noninteractive
RUN echo "Installing base packages" && \
    apt-get -y update && apt-get install -y nano sudo curl wget auditd vim tmux git unzip systemtap-sdt-dev \
    bpftrace \
    && rm -rf /var/lib/apt/lists/*

# install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# build stage
FROM main AS builder

RUN apt-get -y update && apt-get install -y \
    autoconf \
    binutils \
    bison \
    flex \
    gcc \
    g++ \
    git \
    libprotobuf-dev \
    libnl-route-3-dev \
    libtool \
    make \
    cmake \
    pkg-config \
    protobuf-compiler
# \
#    && rm -rf /var/lib/apt/lists/*

RUN echo "Installing prerequisites" && \
    apt-get install -y \
    build-essential \
    libsqlite3-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libssl-dev \
    libreadline-dev \
    libffi-dev

RUN echo "Installing python with dtrace" && \
    curl -o Python-${PYTHON_VERSION}.tgz https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && tar -xzf Python-${PYTHON_VERSION}.tgz && \
    cd Python-${PYTHON_VERSION} && ./configure --with-dtrace --prefix=/usr/local/openssl --prefix=$(pwd) --with-ensurepip=install && make && make install && rm ../Python-${PYTHON_VERSION}.tgz

#RUN echo "Installing bpftrace" && \
#    wget https://github.com/iovisor/bpftrace/releases/download/${BPFTRACE_VERSION}/bpftrace && \
#    chmod +x bpftrace && \
#    mv bpftrace /bin && \
#    echo "Done building bpftrace"

# Install nsjail: taken from https://github.com/google/nsjail/blob/master/Dockerfile
#RUN git clone https://github.com/google/nsjail.git /nsjail && cd /nsjail && make && mv /nsjail/nsjail /bin && rm -rf -- /nsjail

# Install configured python
RUN uv venv --python /workspace/Python-${PYTHON_VERSION}/python .venv

COPY ./README.md ./pyproject.toml ./uv.lock ./

# Python dependencies for examples
RUN uv sync --frozen --no-dev --no-install-project && uv pip install fastapi uvicorn

FROM main

WORKDIR /workspace

COPY ./README.md ./pyproject.toml ./uv.lock ./

COPY --from=builder /workspace/.venv /workspace/.venv
COPY --from=builder /workspace/Python-${PYTHON_VERSION} /workspace/Python-${PYTHON_VERSION}

ENV BPFTRACE_KERNEL_SOURCE=/kernel/usr/src/linux-headers
COPY docker/docker/setup.sh .

# Open port 8000 for demos/examples with networking
EXPOSE 8000
CMD ["/bin/sh", "/workspace/setup.sh"]
