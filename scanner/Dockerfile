FROM kalilinux/kali-rolling
ENV PYTHONUNBUFFERED=1
ENV HOME=/root

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    sqlmap \
    nuclei \
    hydra \
    ffuf \
    seclists \
    tor \
    python3 \
    python3-pip \
    bsdextrautils \
    whatweb \
    dnsutils \
    curl \
    wget \
    unzip \
    git \
    libpq-dev \
    iproute2 \
    iputils-ping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && chmod +x /opt/testssl.sh/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

RUN wget -q "https://github.com/hahwul/dalfox/releases/download/v2.9.2/dalfox_2.9.2_linux_amd64.tar.gz" \
    -O /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /tmp/ \
    && mv /tmp/dalfox /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm /tmp/dalfox.tar.gz

RUN wget -q "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip" \
    -O /tmp/katana.zip \
    && unzip -o /tmp/katana.zip katana -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana \
    && rm /tmp/katana.zip

RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git \
    /root/.local/nuclei-templates \
    && echo "Templates: $(find /root/.local/nuclei-templates -name '*.yaml' | wc -l)"

WORKDIR /scanner
COPY requirements.txt .
RUN pip3 install -r requirements.txt --break-system-packages
COPY . .
RUN chmod +x /scanner/entrypoint.sh
EXPOSE 5001
CMD ["/bin/bash", "/scanner/entrypoint.sh"]
