#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid, urllib.request, ssl, sys
API="https://engage.begweb.com"; REG="/api/v4/session/register/android"; FETCH="/api/v4/subscription/fetch/android"
CERT="c11b5d7bac4365a25ae1bc98ef8c0ba04e1e1b84fe84ef58ba305358a33cc34d"; VAULT="begzar-sign-v1"
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

def go(name, token, secret, device, path="/subscription/fetch/android", body=b"{}"):
    nonce=secrets.token_hex(16); ts=str(int(time.time()))
    key=hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    bh=hashlib.sha256(body).hexdigest()
    sig=hmac.new(key, f"POST\n{path}\n{ts}\n{nonce}\n{bh}".encode(), hashlib.sha256).hexdigest()
    integ=hashlib.sha256(f"{CERT}|{device}|{VAULT}".encode()).hexdigest()
    headers={"X-Begzar-Device-Id":device,"X-Begzar-Session-Key":token,"X-Begzar-Nonce":nonce,"X-Begzar-Timestamp":ts,"X-Begzar-Integrity":integ,"X-Begzar-Signature":sig}
    code, resp=http(FETCH, body, headers)
    text=resp.decode("utf-8","replace")
    print(f"{name}: {code} {text[:150]} magic={resp[:4]!r}")
    if code==200 or resp.startswith(b"BGZ4"):
        open("begzar_hit.bin","wb").write(resp); print("SUCCESS", name); return True
    return False

def main():
    st, raw=http(REG,b"{}"); print("register", st, raw[:200])
    if st!=200: return 1
    token=json.loads(raw)["session_token"]; secret=base64.b64decode(token)
    uuid_dev=str(uuid.uuid4())
    for name, device, path in [
        ("uuid_default", uuid_dev, "/subscription/fetch/android"),
        ("device_is_cert", CERT, "/subscription/fetch/android"),
        ("device_is_cert_path_full", CERT, FETCH),
        ("device_empty", "", "/subscription/fetch/android"),
        ("device_android", "android", "/subscription/fetch/android"),
        ("device_begzar", "cloud.begzar.begzar", "/subscription/fetch/android"),
    ]:
        if go(name, token, secret, device, path=path): return 0
        time.sleep(0.2)
    # Try: integrity uses cert|device|vault but derive uses only device as empty and cert from app equals expected
    # Try signing without derive using PBKDF
    print("ALL_FAILED"); return 2
if __name__=="__main__":
    raise SystemExit(main())
