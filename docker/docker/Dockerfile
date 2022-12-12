ARG KERNEL_VERSION

FROM linuxkit/kernel:${KERNEL_VERSION} as ksrc
FROM ubuntu:20.04 AS build

ARG BPFTRACE_VERSION
ARG PYTHON_VERSION

WORKDIR /kernel
COPY --from=ksrc /kernel-dev.tar .
RUN tar xf kernel-dev.tar

WORKDIR /workspace
ARG DEBIAN_FRONTEND=noninteractive

# TODO: add openssl (longer build time, but pip will work for our interpreter)
RUN echo "Installing prerequisites" && \
    apt-get update && apt-get install nano sudo build-essential libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev curl wget auditd vim tmux git binutils unzip gcc systemtap-sdt-dev cmake zlib1g-dev -y
RUN echo "Installing python with dtrace" && \
    curl -o Python-${PYTHON_VERSION}.tgz https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && tar -xzf Python-${PYTHON_VERSION}.tgz && \
    cd Python-${PYTHON_VERSION} && ./configure --with-dtrace --prefix=/usr/local/openssl --prefix=$(pwd) --with-ensurepip=install && make && make install && \
    rm -rf $WORKDIR/Python-3.10.0.tgz
RUN echo "Installing bpftrace" && \ 
    wget https://github.com/iovisor/bpftrace/releases/download/${BPFTRACE_VERSION}/bpftrace && \
    chmod +x bpftrace && \
    mv bpftrace /bin && \
    echo "Done building bpftrace" && \
    mv /kernel/usr/src/linux-headers* /kernel/usr/src/linux-headers && \
    rm /workspace/Python-3.10.0.tgz
RUN Python-3.10.0/python -m pip install --no-cache fire pyyaml

ENV BPFTRACE_KERNEL_SOURCE=/kernel/usr/src/linux-headers
COPY setup.sh .
COPY sandbox.bt .
COPY trace.bt .
COPY trace.sh .
COPY run_sandbox.sh .
RUN chmod 755 sandbox.bt run_sandbox.sh trace.bt  trace.sh
RUN \
   echo 'export PYTHONPATH="/workspace/Python-3.10.0/python:$PYTHONPATH"' >> /root/.bashrc && \
   echo 'alias python="/workspace/Python-3.10.0/python"' >> /root/.bashrc && \
   echo 'alias pip="/workspace/Python-3.10.0/bin/pip3"' >> /root/.bashrc && \
   echo 'alias secimport-shell="/workspace/trace.sh"' >> /root/.bashrc

ENTRYPOINT ["/bin/sh", "/workspace/setup.sh"]
