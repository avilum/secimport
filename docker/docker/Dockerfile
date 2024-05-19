ARG KERNEL_VERSION

#FROM --platform=linux/amd64 linuxkit/kernel:${KERNEL_VERSION} as ksrc
FROM docker/for-desktop-kernel:5.10.25-6594e668feec68f102a58011bb42bd5dc07a7a9b as ksrc
FROM --platform=linux/amd64 ubuntu:latest AS build

ARG BPFTRACE_VERSION
ARG PYTHON_VERSION

WORKDIR /kernel
COPY --from=ksrc /kernel-dev.tar .
RUN tar xf kernel-dev.tar

WORKDIR /workspace
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && apt-get install -y \
    autoconf \
    bison \
    flex \
    gcc \
    g++ \
    git \
    libprotobuf-dev \
    libnl-route-3-dev \
    libtool \
    make \
    pkg-config \
    protobuf-compiler
# \
#    && rm -rf /var/lib/apt/lists/*

RUN echo "Installing prerequisites" && \
    apt-get update && apt-get install nano sudo build-essential libsqlite3-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev curl wget auditd vim tmux git binutils unzip gcc systemtap-sdt-dev cmake zlib1g-dev -y

RUN echo "Installing python with dtrace" && \
    curl -o Python-${PYTHON_VERSION}.tgz https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && tar -xzf Python-${PYTHON_VERSION}.tgz && \
    cd Python-${PYTHON_VERSION} && ./configure --with-dtrace --prefix=/usr/local/openssl --prefix=$(pwd) --with-ensurepip=install && make && make install

RUN echo "Installing bpftrace" && \
    wget https://github.com/iovisor/bpftrace/releases/download/${BPFTRACE_VERSION}/bpftrace && \
    chmod +x bpftrace && \
    mv bpftrace /bin && \
    echo "Done building bpftrace" && \
    mv /kernel/usr/src/linux-headers* /kernel/usr/src/linux-headers

# Install nsjail: taken from https://github.com/google/nsjail/blob/master//Dockerfile=
#RUN git clone https://github.com/google/nsjail.git /nsjail && cd /nsjail && make && mv /nsjail/nsjail /bin && rm -rf -- /nsjail

# Python dependencies for examples
RUN /workspace/Python-${PYTHON_VERSION}/python -m pip install --upgrade pip && Python-${PYTHON_VERSION}/python -m pip install pyyaml fire fastapi uvicorn --user -U

ENV BPFTRACE_KERNEL_SOURCE=/kernel/usr/src/linux-headers
COPY setup.sh .

# Open port 8000 for demos/examples with networking
EXPOSE 8000
ENTRYPOINT ["/bin/sh", "/workspace/setup.sh"]

