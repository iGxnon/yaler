FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Network capture and analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump iproute2 iptables \
    tshark wireshark-common \
    curl gnupg ca-certificates \
    procps && \
    rm -rf /var/lib/apt/lists/*

# Zeek from official OpenSUSE/Zeek repository for Debian 12
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
        > /etc/apt/sources.list.d/zeek.list && \
    curl -fsSL \
        https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg && \
    apt-get update && apt-get install -y --no-install-recommends zeek && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:$PATH"

COPY entrypoint.sh /entrypoint.sh
COPY analyze.sh /analyze.sh
RUN chmod +x /entrypoint.sh /analyze.sh

ENTRYPOINT ["/entrypoint.sh"]
