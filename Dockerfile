FROM ubuntu:22.04

# Instala apenas o necessário
RUN apt update && apt-get install -y \
    python3 python3-pip \
    tcpdump \
    rsh-redone-client \
    rsh-redone-server \
    xinetd \
    net-tools \
    netcat-openbsd \
    iproute2 iputils-ping \
    iptables \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install numpy rich scapy requests