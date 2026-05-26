"""
Shared utilities: URL parsing, User-Agent rotation, evasion headers, timing.
"""
import random
import time


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "en-GB,en;q=0.8,en-US;q=0.7",
    "ar-TN,ar;q=0.9,fr;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
]


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def random_xff() -> str:
    return (f"{random.randint(10, 200)}."
            f"{random.randint(0, 254)}."
            f"{random.randint(0, 254)}."
            f"{random.randint(1, 254)}")


def evasion_headers() -> dict:
    return {
        "User-Agent":                random_ua(),
        "X-Forwarded-For":           random_xff(),
        "X-Real-IP":                 random_xff(),
        "X-Originating-IP":          random_xff(),
        "Accept-Language":           random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding":           "gzip, deflate, br",
        "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "DNT":                       "1",
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control":             random.choice(["no-cache", "max-age=0", "no-store"]),
    }


def random_sleep(min_s: float = 0.1, max_s: float = 1.0):
    time.sleep(random.uniform(min_s, max_s))


def phase_sleep(scan_speed: str = "normal"):
    if scan_speed == "stealth":
        time.sleep(random.uniform(5.0, 15.0))
    else:
        time.sleep(random.uniform(0.5, 2.0))


def extract_host(url: str) -> str:
    return (url.replace("https://", "")
               .replace("http://", "")
               .split("/")[0]
               .split(":")[0])


def extract_host_port(url: str):
    part = (url.replace("https://", "")
               .replace("http://", "")
               .split("/")[0])
    if ":" in part:
        host, port = part.rsplit(":", 1)
        return host, port
    return part, "80" if url.startswith("http://") else "443"
