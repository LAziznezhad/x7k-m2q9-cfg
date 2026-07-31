#!/usr/bin/env python3
"""One-shot Begzar v4 signature probe for GitHub Actions egress."""
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

def integ(device: str) -> str:
    return hashlib.sha256(f"{CERT}|{device}|{VAULT}".encode()).hexdigest()

def main() -> int:
    st, raw = http(REG, b"{}")
    print("register", st, raw[:300])
    if st != 200:
        return 1
    data = json.loads(raw)
    token = data["session_token"]
    secret = base64.b64decode(token)
    device = str(uuid.uuid4())
    print("token_len", len(token), "secret_len", len(secret), "device", device)

    def attempt(name, *, sign_path="/subscription/fetch/android", secret_bytes=secret, derive_msg=None, body=b"{}", method="POST", url_path=FETCH, sig_fmt="hex"):
        nonce = secrets.token_hex(16)
        ts = str(int(time.time()))
        body_hash = hashlib.sha256(body).hexdigest()
        msg = derive_msg if derive_msg is not None else f"{CERT}|{device}|{VAULT}".encode()
        key = hmac.new(secret_bytes, msg, hashlib.sha256).digest()
        canon = f"{method}\n{sign_path}\n{ts}\n{nonce}\n{body_hash}".encode()
        dig = hmac.new(key, canon, hashlib.sha256).digest()
        sig = base64.b64encode(dig).decode() if sig_fmt == "b64" else dig.hex()
        headers = {
            "X-Begzar-Device-Id": device,
            "X-Begzar-Session-Key": token,
            "X-Begzar-Nonce": nonce,
            "X-Begzar-Timestamp": ts,
            "X-Begzar-Integrity": integ(device),
            "X-Begzar-Signature": sig,
        }
        code, resp = http(url_path, body, headers, method=method)
        text = resp.decode("utf-8", "replace")
        print(f"{name}: {code} {text[:180]} magic={resp[:4]!r}")
        if code == 200 or resp.startswith(b"BGZ4"):
            open("/tmp/begzar_hit.bin", "wb").write(resp)
            print("SUCCESS", name, "len", len(resp))
            # try decrypt preview
            if resp.startswith(b"BGZ4"):
                print("BGZ4 envelope ok")
            return True
        return False

    variants = [
        ("default", {}),
        ("path_full", {"sign_path": FETCH}),
        ("path_noslash", {"sign_path": "subscription/fetch/android"}),
        ("body_empty", {"body": b""}),
        ("secret_utf8", {"secret_bytes": token.encode()}),
        ("derive_empty_dev", {"derive_msg": f"{CERT}||{VAULT}".encode()}),
        ("derive_cert_as_dev", {"derive_msg": f"{CERT}|{CERT}|{VAULT}".encode()}),
        ("derive_vault_mid", {"derive_msg": f"{CERT}|{VAULT}|{device}".encode()}),
        ("sig_b64", {"sig_fmt": "b64"}),
        ("get_promotions", {"method": "GET", "url_path": "/api/v4/promotions/list", "sign_path": "/promotions/list", "body": b""}),
        # Maybe Session-Key should be raw base64 without JSON escaping issues - already parsed
        # Try body as JSON with device_id
        ("body_device", {"body": json.dumps({"device_id": device}, separators=(",", ":")).encode()}),
        ("body_deviceId", {"body": json.dumps({"deviceId": device}, separators=(",", ":")).encode()}),
        # Double HMAC: sign with HMAC(secret, canon) where secret is already derived? 
        ("no_derive_raw",),
    ]
    # raw hmac without derive
    nonce = secrets.token_hex(16); ts = str(int(time.time())); bh = hashlib.sha256(b"{}").hexdigest()
    canon = f"POST\n/subscription/fetch/android\n{ts}\n{nonce}\n{bh}".encode()
    sig = hmac.new(secret, canon, hashlib.sha256).hexdigest()
    headers = {
        "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
        "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
    }
    code, resp = http(FETCH, b"{}", headers)
    print("raw_no_derive:", code, resp[:160])

    for item in variants:
        if item[0] == "no_derive_raw":
            continue
        name, kwargs = item[0], item[1] if len(item) > 1 else {}
        if attempt(name, **kwargs):
            return 0
        time.sleep(0.2)
    # Extra: maybe Integrity uses cert|device|vault but signature path uses only secret as key over method\nurl\nts\nnonce\nbody
    extra = []
    body = b"{}"
    for sign_path in ("/subscription/fetch/android", FETCH, "/api/v4/subscription/fetch/android"):
        for keymaker in (
            lambda: hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest(),
            lambda: hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()[:16],
            lambda: hashlib.sha256(secret + f"{CERT}|{device}|{VAULT}".encode()).digest(),
            lambda: hashlib.pbkdf2_hmac("sha256", secret, f"{CERT}|{device}|{VAULT}".encode(), 1000, 32),
        ):
            nonce = secrets.token_hex(16); ts = str(int(time.time())); bh = hashlib.sha256(body).hexdigest()
            key = keymaker()
            canon = f"POST\n{sign_path}\n{ts}\n{nonce}\n{bh}".encode()
            sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
            headers = {
                "X-Begzar-Device-Id": device, "X-Begzar-Session-Key": token, "X-Begzar-Nonce": nonce,
                "X-Begzar-Timestamp": ts, "X-Begzar-Integrity": integ(device), "X-Begzar-Signature": sig,
            }
            code, resp = http(FETCH, body, headers)
            text = resp.decode("utf-8", "replace")
            name = f"extra path={sign_path} key={key[:4].hex()}"
            print(f"{name}: {code} {text[:120]}")
            if code == 200 or resp.startswith(b"BGZ4"):
                open("/tmp/begzar_hit.bin", "wb").write(resp)
                print("SUCCESS", name)
                return 0
            if "Invalid signature" not in text and "ip_blocked" not in text:
                print("INTERESTING", name, text[:200])
            time.sleep(0.05)
    print("ALL_FAILED")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
