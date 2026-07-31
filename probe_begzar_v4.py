#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid, urllib.request, ssl, sys
API="https://engage.begweb.com"
CERT="c11b5d7bac4365a25ae1bc98ef8c0ba04e1e1b84fe84ef58ba305358a33cc34d"
VAULT="begzar-sign-v1"
UA={"User-Agent":"BegzarVPN","Accept":"application/json","Content-Type":"application/json","X-Content-Type-Options":"nosniff"}
CTX=ssl.create_default_context()

def http(path, body=b"{}", headers=None, method="POST"):
    req=urllib.request.Request(API+path, data=None if method=="GET" else body, method=method)
    for k,v in UA.items():
        if method=="GET" and k=="Content-Type": continue
        req.add_header(k,v)
    if headers:
        for k,v in headers.items(): req.add_header(k,v)
    try:
        with urllib.request.urlopen(req, timeout=30, context=CTX) as r: return r.status, r.read()
    except Exception as e:
        code=getattr(e,"code",None); raw=b""
        if hasattr(e,"read"):
            try: raw=e.read()
            except Exception: pass
        return code, raw or str(e).encode()

def integ(device):
    return hashlib.sha256(f"{CERT}|{device}|{VAULT}".encode()).hexdigest()

def sign(method, path, ts, nonce, body, secret, device):
    key=hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    bh=hashlib.sha256(body).hexdigest()
    return hmac.new(key, f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{bh}".encode(), hashlib.sha256).hexdigest()

def signed_req(name, token, secret, device, *, path_http, sign_path, body=b"{}", method="POST"):
    nonce=secrets.token_hex(16); ts=str(int(time.time()))
    sig=sign(method, sign_path, ts, nonce, body if method!="GET" else b"", secret, device)
    headers={
        "X-Begzar-Device-Id":device,
        "X-Begzar-Session-Key":token,
        "X-Begzar-Nonce":nonce,
        "X-Begzar-Timestamp":ts,
        "X-Begzar-Integrity":integ(device),
        "X-Begzar-Signature":sig,
    }
    code, resp=http(path_http, body if method!="GET" else None, headers, method=method)
    text=resp.decode("utf-8","replace")
    print(f"{name}: {code} {text[:180]} magic={resp[:4]!r}")
    if code==200 or resp.startswith(b"BGZ4"):
        open("begzar_hit.bin","wb").write(resp); print("SUCCESS", name); return True
    return False

def main():
    device=str(uuid.uuid4())
    # A) register plain
    st, raw=http("/api/v4/session/register/android", b"{}")
    print("register_plain", st, raw[:180])
    # B) register with device headers (no signature)
    st2, raw2=http("/api/v4/session/register/android", b"{}", {
        "X-Begzar-Device-Id":device,
        "X-Begzar-Integrity":integ(device),
    })
    print("register_with_device", st2, raw2[:180])
    # C) register with device in body
    body_reg=json.dumps({"device_id":device},separators=(",",":")).encode()
    st3, raw3=http("/api/v4/session/register/android", body_reg, {
        "X-Begzar-Device-Id":device,
        "X-Begzar-Integrity":integ(device),
    })
    print("register_body_device", st3, raw3[:180])
    token=None
    for st,raw in [(st,raw),(st2,raw2),(st3,raw3)]:
        if st==200:
            try:
                token=json.loads(raw)["session_token"]; break
            except Exception:
                pass
    if not token:
        print("no token"); return 1
    secret=base64.b64decode(token)
    print("using token len", len(secret), "device", device)
    attempts=[
        ("fetch_android", "/api/v4/subscription/fetch/android", "/subscription/fetch/android", b"{}", "POST"),
        ("fetch_win", "/api/v4/subscription/fetch/", "/subscription/fetch/", b"{}", "POST"),
        ("fetch_android_body_dev", "/api/v4/subscription/fetch/android", "/subscription/fetch/android", body_reg, "POST"),
        ("fetch_fullpath_sign", "/api/v4/subscription/fetch/android", "/api/v4/subscription/fetch/android", b"{}", "POST"),
        ("promo_get", "/api/v4/promotions/list", "/promotions/list", b"", "GET"),
        ("promo_get_slash", "/api/v4/promotions/list", "/promotions/list/", b"", "GET"),
        ("geo_signed", "/api/v4/network/geo", "/network/geo", b"", "GET"),
        ("empty_body", "/api/v4/subscription/fetch/android", "/subscription/fetch/android", b"", "POST"),
        ("body_null", "/api/v4/subscription/fetch/android", "/subscription/fetch/android", b"null", "POST"),
    ]
    for name, http_path, sign_path, body, method in attempts:
        if signed_req(name, token, secret, device, path_http=http_path, sign_path=sign_path, body=body, method=method):
            return 0
        time.sleep(0.15)
    # D) reuse same device from register_body_device token specifically
    if st3==200:
        token3=json.loads(raw3)["session_token"]; secret3=base64.b64decode(token3)
        if signed_req("bound_device_fetch", token3, secret3, device, path_http="/api/v4/subscription/fetch/android", sign_path="/subscription/fetch/android", body=body_reg):
            return 0
    # E) try secret = token utf-8, and HMAC key/msg swap
    nonce=secrets.token_hex(16); ts=str(int(time.time())); body=b"{}"; path="/subscription/fetch/android"
    for name, secret_b, key_first in [
        ("utf8_secret", token.encode(), True),
        ("swap_hmac", secret, False),
    ]:
        msg=f"{CERT}|{device}|{VAULT}".encode()
        if key_first:
            key=hmac.new(secret_b, msg, hashlib.sha256).digest()
        else:
            key=hmac.new(msg, secret_b, hashlib.sha256).digest()
        bh=hashlib.sha256(body).hexdigest()
        sig=hmac.new(key, f"POST\n{path}\n{ts}\n{nonce}\n{bh}".encode(), hashlib.sha256).hexdigest()
        # new nonce each
        nonce=secrets.token_hex(16); ts=str(int(time.time()))
        sig=hmac.new(key, f"POST\n{path}\n{ts}\n{nonce}\n{bh}".encode(), hashlib.sha256).hexdigest()
        headers={"X-Begzar-Device-Id":device,"X-Begzar-Session-Key":token,"X-Begzar-Nonce":nonce,"X-Begzar-Timestamp":ts,"X-Begzar-Integrity":integ(device),"X-Begzar-Signature":sig}
        code, resp=http("/api/v4/subscription/fetch/android", body, headers)
        print(f"{name}: {code} {resp[:120]!r}")
        if code==200 or resp.startswith(b"BGZ4"):
            print("SUCCESS", name); return 0
    print("ALL_FAILED"); return 2
if __name__=="__main__":
    raise SystemExit(main())
