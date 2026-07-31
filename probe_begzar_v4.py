#!/usr/bin/env python3
"""Probe Session-Key encoding and native-faithful signing."""
from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid, urllib.request, ssl, sys, urllib.parse
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

def integ(device: str) -> str:
    return hashlib.sha256(f"{CERT}|{device}|{VAULT}".encode()).hexdigest()

def make_sig(secret: bytes, device: str, method: str, path: str, ts: str, nonce: str, body: bytes) -> str:
    key = hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    bh = hashlib.sha256(body).hexdigest()
    canon = f"{method}\n{path}\n{ts}\n{nonce}\n{bh}".encode()
    return hmac.new(key, canon, hashlib.sha256).hexdigest()

def attempt(name, token, secret, device, *, session_key=None, path="/subscription/fetch/android", body=b"{}"):
    session_key = token if session_key is None else session_key
    nonce = secrets.token_hex(16)
    ts = str(int(time.time()))
    sig = make_sig(secret, device, "POST", path, ts, nonce, body)
    headers = {
        "X-Begzar-Device-Id": device,
        "X-Begzar-Session-Key": session_key,
        "X-Begzar-Nonce": nonce,
        "X-Begzar-Timestamp": ts,
        "X-Begzar-Integrity": integ(device),
        "X-Begzar-Signature": sig,
    }
    code, resp = http(FETCH, body, headers)
    text = resp.decode("utf-8", "replace")
    print(f"{name}: {code} {text[:160]} magic={resp[:4]!r}")
    if code == 200 or resp.startswith(b"BGZ4"):
        open("begzar_hit.bin", "wb").write(resp)
        print("SUCCESS", name, "len", len(resp))
        return True
    return False

def main() -> int:
    st, raw = http(REG, b"{}")
    print("register", st, raw[:300])
    if st != 200:
        return 1
    token = json.loads(raw)["session_token"]
    secret = base64.b64decode(token)
    device = str(uuid.uuid4())
    print("token", token)
    print("has_plus", "+" in token, "has_slash", "/" in token)

    variants = [
        ("default", {}),
        ("sk_urlencoded", {"session_key": urllib.parse.quote(token, safe="")}),
        ("sk_quote_plus", {"session_key": urllib.parse.quote_plus(token)}),
        ("sk_replace_plus", {"session_key": token.replace("+", "-").replace("/", "_")}),
        ("sk_b64url_nopad", {"session_key": base64.urlsafe_b64encode(secret).decode().rstrip("=")}),
        ("sk_b64url_pad", {"session_key": base64.urlsafe_b64encode(secret).decode()}),
        ("secret_from_urlsafe_decode",),  # special
        ("path_full", {"path": FETCH}),
        ("device_no_dash", {"device": device.replace("-", "")}),
    ]

    # special: decode token as urlsafe
    try:
        secret_url = base64.urlsafe_b64decode(token + "==")
    except Exception:
        secret_url = secret

    for item in variants:
        name = item[0]
        kwargs = item[1] if len(item) > 1 else {}
        if name == "secret_from_urlsafe_decode":
            if attempt(name, token, secret_url, device):
                return 0
            continue
        if "device" in kwargs:
            dev = kwargs.pop("device")
            # need to recompute with that device - hack by temp
            if attempt(name, token, secret, dev, **kwargs):
                return 0
            continue
        if attempt(name, token, secret, device, **kwargs):
            return 0
        time.sleep(0.15)

    # Fresh nonce each; try signing with bodyHash UPPERCASE
    nonce = secrets.token_hex(16); ts = str(int(time.time())); body = b"{}"
    key = hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    bh = hashlib.sha256(body).hexdigest().upper()
    canon = f"POST\n/subscription/fetch/android\n{ts}\n{nonce}\n{bh}".encode()
    sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
    headers = {
        "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
        "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
    }
    code, resp = http(FETCH, body, headers)
    print("bodyhash_upper:", code, resp[:160])

    # Signature uppercase
    nonce = secrets.token_hex(16); ts = str(int(time.time()))
    sig = make_sig(secret, device, "POST", "/subscription/fetch/android", ts, nonce, body).upper()
    headers = {
        "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
        "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
    }
    code, resp = http(FETCH, body, headers)
    print("sig_upper:", code, resp[:160])

    print("ALL_FAILED")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
