#!/bin/bash
# SecuriScan scanner entrypoint

# Nuclei templates
COUNT=$(find /root/.local/nuclei-templates -name "*.yaml" 2>/dev/null | wc -l)
echo "[STARTUP] Nuclei templates: $COUNT templates ready"

# Start Tor for stealth mode
tor --RunAsDaemon 1 --SocksPort 9050 --Log "notice file /tmp/tor.log" 2>/dev/null
sleep 2
if curl -s --socks5 127.0.0.1:9050 --connect-timeout 5 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
    echo "[STARTUP] Tor proxy ready on 127.0.0.1:9050"
else
    echo "[STARTUP] Tor proxy started (verification skipped)"
fi

exec python3 -u scanner_agent.py
