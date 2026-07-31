#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid, urllib.request, ssl, sys
API="https://engage.begweb.com"
REG="/api/v4/session/register/android"
FETCH="/api/v4/subscription/fetch/android"
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

def attempt(name, token, secret, device, *, path, body, nonce, ts, key_msg=None, key=None, canon=None, sig=None, integ=None, session_key=None):
    body_hash=hashlib.sha256(body).hexdigest()
    if key is None:
        msg = key_msg if key_msg is not None else f"{CERT}|{device}|{VAULT}".encode()
        key=hmac.new(secret, msg, hashlib.sha256).digest()
    if canon is None:
        canon=f"POST\n{path}\n{ts}\n{nonce}\n{body_hash}".encode()
    if sig is None:
        sig=hmac.new(key, canon, hashlib.sha256).hexdigest()
    if integ is None:
        integ=hashlib.sha256(f"{CERT}|{device}|{VAULT}".encode()).hexdigest()
    headers={
        "X-Begzar-Device-Id":device,
        "X-Begzar-Session-Key": token if session_key is None else session_key,
        "X-Begzar-Nonce":nonce,
        "X-Begzar-Timestamp":ts,
        "X-Begzar-Integrity":integ,
        "X-Begzar-Signature":sig,
    }
    code, resp=http(FETCH, body, headers)
    text=resp.decode("utf-8","replace")
    print(f"{name}: {code} {text[:120]} magic={resp[:4]!r}")
    if code==200 or resp.startswith(b"BGZ4"):
        open("begzar_hit.bin","wb").write(resp)
        print("SUCCESS", name)
        return True
    return False

def main():
    st, raw=http(REG,b"{}")
    print("register", st, raw[:200])
    if st!=200: return 1
    token=json.loads(raw)["session_token"]
    secret=base64.b64decode(token)
    device=str(uuid.uuid4())
    print("device", device)
    tests=[]
    def add(name, **kw):
        tests.append((name, kw))
    # nonce formats
    for nname, nonce in [
        ("hex16", secrets.token_hex(16)),
        ("hex8", secrets.token_hex(8)),
        ("uuid", str(uuid.uuid4())),
        ("b64", base64.b64encode(secrets.token_bytes(16)).decode()),
        ("b64url", base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")),
    ]:
        add(f"nonce_{nname}", path="/subscription/fetch/android", body=b"{}", nonce=nonce, ts=str(int(time.time())))
    # path variants with fresh uuid nonce
    for path in [
        "/subscription/fetch/android",
        "subscription/fetch/android",
        "/api/v4/subscription/fetch/android",
        "api/v4/subscription/fetch/android",
        "/subscription/fetch/",
        "/subscription/fetch",
        "https://engage.begweb.com/api/v4/subscription/fetch/android",
    ]:
        add(f"path_{path}", path=path, body=b"{}", nonce=str(uuid.uuid4()), ts=str(int(time.time())))
    # body variants
    for bname, body in [
        ("obj", b"{}"),
        ("empty", b""),
        ("device", json.dumps({"device_id":device},separators=(",",":")).encode()),
        ("deviceId", json.dumps({"deviceId":device},separators=(",",":")).encode()),
        ("null", b"null"),
    ]:
        add(f"body_{bname}", path="/subscription/fetch/android", body=body, nonce=str(uuid.uuid4()), ts=str(int(time.time())))
    # key / canonical experiments
    ts=str(int(time.time())); nonce=str(uuid.uuid4()); body=b"{}"; bh=hashlib.sha256(body).hexdigest(); path="/subscription/fetch/android"
    key=hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    integ=hashlib.sha256(f"{CERT}|{device}|{VAULT}".encode()).hexdigest()
    add("canon_with_integ", path=path, body=body, nonce=nonce, ts=ts,
        canon=f"POST\n{path}\n{ts}\n{nonce}\n{bh}\n{integ}".encode())
    add("canon_method_path_only", path=path, body=body, nonce=str(uuid.uuid4()), ts=str(int(time.time())),
        canon=lambda: None)
    # fix lambda - rebuild properly below
    tests = [t for t in tests if t[0] != "canon_method_path_only"]
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("canon_colon", path=path, body=body, nonce=n, ts=t,
        canon=f"POST:{path}:{t}:{n}:{bh}".encode())
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("canon_no_bodyhash", path=path, body=body, nonce=n, ts=t,
        canon=f"POST\n{path}\n{t}\n{n}".encode())
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("key_is_integrity_hex", path=path, body=body, nonce=n, ts=t, key=bytes.fromhex(integ))
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("key_is_integrity_utf8", path=path, body=body, nonce=n, ts=t, key=integ.encode())
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("secret_utf8_derive", path=path, body=body, nonce=n, ts=t, key=hmac.new(token.encode(), f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest())
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("no_derive_secret", path=path, body=body, nonce=n, ts=t, key=secret)
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("derive_vault_dev_cert", path=path, body=body, nonce=n, ts=t, key_msg=f"{VAULT}|{device}|{CERT}".encode())
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("ts_ms", path=path, body=body, nonce=n, ts=str(int(time.time()*1000)))
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("session_quoted", path=path, body=body, nonce=n, ts=t, session_key=f'"{token}"')
    n=str(uuid.uuid4()); t=str(int(time.time()))
    # Double HMAC: sign with HMAC(secret, canon) then hex — already no_derive
    # Maybe signature is base64 of hmac
    n=str(uuid.uuid4()); t=str(int(time.time())); bh=hashlib.sha256(body).hexdigest()
    key=hmac.new(secret, f"{CERT}|{device}|{VAULT}".encode(), hashlib.sha256).digest()
    raw=hmac.new(key, f"POST\n{path}\n{t}\n{n}\n{bh}".encode(), hashlib.sha256).digest()
    add("sig_b64", path=path, body=body, nonce=n, ts=t, sig=base64.b64encode(raw).decode())
    n=str(uuid.uuid4()); t=str(int(time.time()))
    raw=hmac.new(key, f"POST\n{path}\n{t}\n{n}\n{bh}".encode(), hashlib.sha256).digest()
    add("sig_upper", path=path, body=body, nonce=n, ts=t, sig=raw.hex().upper())
    # integrity = native style, but maybe device empty in integrity only
    n=str(uuid.uuid4()); t=str(int(time.time()))
    add("integ_empty_device", path=path, body=body, nonce=n, ts=t,
        integ=hashlib.sha256(f"{CERT}||{VAULT}".encode()).hexdigest())
    # Maybe path for sign is fetch path used by dio options.uri.path with base
    for name, kw in tests:
        if attempt(name, token, secret, device, **kw):
            return 0
        time.sleep(0.12)
    print("ALL_FAILED", len(tests))
    return 2
if __name__=="__main__":
    raise SystemExit(main())
