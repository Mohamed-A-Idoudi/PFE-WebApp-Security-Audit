FROM kalilinux/kali-rolling

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    python3 \
    python3-pip \
    curl \
    wget \
    unzip \
    libpq-dev \
    iproute2 \
    iputils-ping \
    dnsutils \
    net-tools \
    && apt-get clean

# Install nuclei from binary release
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /scanner
COPY requirements.txt .
RUN pip3 install -r requirements.txt --break-system-packages

COPY . .

EXPOSE 5001
CMD ["python3", "-u", "scanner_agent.py"]