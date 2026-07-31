#!/usr/bin/env python3
"""Begzar v4 auth header semantics probe."""
from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid, urllib.request, ssl, sys
API = "https://engage.begweb.com"
REG = "/api/v4/session/register/android"
FETCH = "/api/v4/subscription/fetch/android"
CERT = "c11b5d7bac4365a25ae1bc98ef8c0ba04e1e1b84fe84ef58ba305358a33cc34d"
VAULT = "begzar-sign-v1"
UA = {"User-Agent": "BegzarVPN", "Accept": "application/json", "Content-Type": "application/json", "X-Content-Type-Options": "nosniff"}
CTX = ssl.create_default_context()

def http(path, body=b"{}", headers=None, method="POST"):
    req = urllib.request.Request(API + path, data=None if method == "GET" else body, method=method)
    for k, v in UA.items():
        if method == "GET" and k == "Content-Type":
            continue
        req.add_header(k, v)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
            return r.status, r.read()
    except Exception as e:
        code = getattr(e, "code", None)
        raw = b""
        if hasattr(e, "read"):
            try:
                raw = e.read()
            except Exception:
                pass
        return code, raw or str(e).encode()

def integ(device: str, cert: str = CERT) -> str:
    return hashlib.sha256(f"{cert}|{device}|{VAULT}".encode()).hexdigest()

def sign(secret: bytes, device: str, method: str, path: str, ts: str, nonce: str, body: bytes, derive_dev: str | None = None) -> str:
    d = device if derive_dev is None else derive_dev
    key = hmac.new(secret, f"{CERT}|{d}|{VAULT}".encode(), hashlib.sha256).digest()
    bh = hashlib.sha256(body).hexdigest()
    canon = f"{method}\n{path}\n{ts}\n{nonce}\n{bh}".encode()
    return hmac.new(key, canon, hashlib.sha256).hexdigest()

def main() -> int:
    st, raw = http(REG, b"{}")
    print("register", st, raw[:300])
    if st != 200:
        return 1
    token = json.loads(raw)["session_token"]
    secret = base64.b64decode(token)
    device = str(uuid.uuid4())
    body = b"{}"
    print("device", device, "token", token)

    def post(name, headers):
        code, resp = http(FETCH, body, headers)
        text = resp.decode("utf-8", "replace")
        print(f"{name}: {code} {text[:160]}")
        return code, resp, text

    nonce = secrets.token_hex(16)
    ts = str(int(time.time()))
    sig = sign(secret, device, "POST", "/subscription/fetch/android", ts, nonce, body)
    base = {
        "X-Begzar-Device-Id": device,
        "X-Begzar-Session-Key": token,
        "X-Begzar-Nonce": nonce,
        "X-Begzar-Timestamp": ts,
        "X-Begzar-Integrity": integ(device),
        "X-Begzar-Signature": sig,
    }
    post("full_default", base)

    # Drop headers one by one
    for drop in list(base):
        h = dict(base)
        del h[drop]
        post(f"drop_{drop}", h)

    # Wrong integrity, correct signature
    h = dict(base)
    h["X-Begzar-Integrity"] = "0" * 64
    post("bad_integrity", h)

    # Wrong signature, correct integrity
    h = dict(base)
    h["X-Begzar-Signature"] = "ab" * 32
    post("bad_signature", h)

    # Wrong device in header but correct in integrity/sign derive
    h = dict(base)
    h["X-Begzar-Device-Id"] = str(uuid.uuid4())
    post("mismatched_device_header", h)

    # Session-Key = secret hex
    h = dict(base)
    h["X-Begzar-Session-Key"] = secret.hex()
    post("session_key_hex", h)

    # Session-Key = secret raw base64 urlsafe
    h = dict(base)
    h["X-Begzar-Session-Key"] = base64.urlsafe_b64encode(secret).decode().rstrip("=")
    post("session_key_b64url", h)

    # Try Authorization header styles
    for k, v in [
        ("Authorization", f"Bearer {token}"),
        ("Authorization", f"Session {token}"),
        ("X-Session-Token", token),
    ]:
        h = dict(base)
        h[k] = v
        post(f"extra_{k}", h)

    # Canonical with CRLF
    nonce = secrets.token_hex(16); ts = str(int(time.time()))
    bh = hashlib.sha256(body).hexdigest()
    key = hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    for sep_name, sep in [("lf", "\n"), ("crlf", "\r\n"), ("cr", "\r")]:
        canon = sep.join(["POST", "/subscription/fetch/android", ts, nonce, bh]).encode()
        sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
        h = {
            "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
            "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
        }
        post(f"sep_{sep_name}", h)

    # Maybe path for android register endpoint style signing of fetch uses same path template with platform
    for path in [
        "/subscription/fetch/android",
        "/api/v4/subscription/fetch/android",
        "https://engage.begweb.com/api/v4/subscription/fetch/android",
        "/api/v4/subscription/fetch/android/",
    ]:
        nonce = secrets.token_hex(16); ts = str(int(time.time()))
        sig = sign(secret, device, "POST", path, ts, nonce, body)
        h = {
            "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
            "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
        }
        post(f"path_{path}", h)

    # Unicorn-independent: try signing key = HMAC(vault, secret) etc
    nonce = secrets.token_hex(16); ts = str(int(time.time())); bh = hashlib.sha256(body).hexdigest()
    for name, key in [
        ("hmac_vault_secret", hmac.new(VAULT.encode(), secret, hashlib.sha256).digest()),
        ("hmac_secret_vault", hmac.new(secret, VAULT.encode(), hashlib.sha256).digest()),
        ("hmac_cert_secret", hmac.new(CERT.encode(), secret, hashlib.sha256).digest()),
        ("sha256_secret_msg", hashlib.sha256(secret + f"{CERT}|{device}|{VAULT}".encode()).digest()),
    ]:
        canon = f"POST\n/subscription/fetch/android\n{ts}\n{nonce}\n{bh}".encode()
        sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
        h = {
            "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
            "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
        }
        post(name, h)

    print("DONE")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
