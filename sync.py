#!/usr/bin/env python3
"""Remote config sync: Begzar (FlyB) + V2VPN (FlyV) + SecretVPN (FlyF) + TopVPN (FlyT) + ExoVPN (FlyExo) + DarkVPN (FlyD)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import ssl
import struct
import sys
import time
import uuid
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.padding import PKCS7
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB8 as AesCFB8
    except ImportError:
        AesCFB8 = modes.CFB8
except ImportError:
    print("Missing dependency: cryptography")
    sys.exit(1)

API_BASE = "https://engage.begweb.com"
REGISTER_PATH = "/api/v4/session/register/android"
FETCH_PATH = "/api/v4/subscription/fetch/android"
SIGN_PATH = "/subscription/fetch/android"
APK_CERT_SHA256 = "c11b5d7bac4365a25ae1bc98ef8c0ba04e1e1b84fe84ef58ba305358a33cc34d"
VAULT_SIGN_INFO = "begzar-sign-v1"
BGZ4_KEY = base64.b64decode("ZvK8P/69/r60RO1BzWe1FJxGFtkwq+bf6he88eAtqVk=")
BGZ4_MAGIC = b"BGZ4"
HEADERS = {
    "User-Agent": "BegzarVPN",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
}
V2_API_URL = "https://api.gem-panel.com/api/v1/apps/app-data"
V2_RAW_URL = (
    "https://raw.githubusercontent.com/s741dev/"
    "5a2cb343b1e6a5c10d5c74b8c78eb580/main/"
    "5c5908ae226133df3db96e6a223b65ee"
)
V2_GITLAB_URL = (
    "https://gitlab.com/s741.dev/"
    "5a2cb343b1e6a5c10d5c74b8c78eb580/-/raw/main/"
    "5c5908ae226133df3db96e6a223b65ee"
)
V2_API_KEY = "af949a03-9abc-42aa-a88a-135eb84f0808"
V2_APP_VERSION = "110.4"
V2_KEY_MATERIAL = (
    "3082058830820370a00302010202146758a70bb36de890068c44ad7aacc3916295d109300d06092a864886f70d01010b05003074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f69643020170d3233303732353038333431325a180f32303533303732353038333431325a3074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f696430820222300d06092a864886f70d01010105000382020f003082020a02820201008c49d0f0fc4021a93314888f9b39e9491c3283eb1f935499c16ba345806532ee28aa4d6379886d896a24035ebb61096e7808aa500bf7581c2e81b75162d129359cb222635eb4c02d8f684f1da7d398aa299135a7d11966dd6a81ca4a170c4666627256e365afceb519ded2bb8f178329a54b48df15153e0983352629bf10a2a8490a1952ac271f80fc739e6275df2387c99d075b0b11e07ba75ca9d66dfc24a84b6fe728a42c14dcbf58f0b7a7afe59f30e6508d13c62972a1bb41b88d5ab6070ef003e39cc52419433cc4817927789762d3106583fa3a2f3cbb7c1ef63eeabd459eca4c40f660eeb5a065c44e599220aecda307b800188bafc85942ef673569071542d5ef25042857326eb6b9bc4742272f135411ab087e180ce98e70436698a08025827ab9ae1378a15c1ddfc1875d55f77e59f92549d8fad1df0221a9604e8ba037f7a9e5158a1323d5adec12ede3d12e05415a729db3f56f682e82e6f88fb52125ab5c405f5a6510cda324a3ff30a8e4167a98e44fbb26bd3296d49b2e84f95de42a020a79034dd350d3d7a6ef2c50c167fa77e32771b9d83cd8ef21fc1c991b9d96a4ef43e8bf17ed3e02eb251d731e36ffc4917a545267abda88ffe6760e9d13d188345a48018066b14fa44b5f35d1833eefc070c839ca96a92ab1780b2d220c47756ae77865be4a491a2f90650cd45ba2fdf00004a85122f518051a230203010001a310300e300c0603551d13040530030101ff300d06092a864886f70d01010b05000382020100187c534df9768e4df70ef7a0f2949e52cb60b7bc825f8d2b809304c90833fcf747e578b21254499acb5ec9ee723e059bded95f4c42aa41a888cf2413cbec5875096009146b374ce841f7b903625204c3c0b391208b2e4c37bee53aa9c1897f3e09be6934185afcad5d734828e1263a06aa781016b21803cd7aaf00950ca8170c3d426b10df90ffe1e1b37ab7dde3cb2364da96d616268af99c5ccdf5a2daea710ce504484bb7d2f43e44e91f781e24de2f75ae13a2b5f18f4b08b9c24474afc47b989809419dfb7af57af727f9f1c542c202626a2dc43a4ed39391346a7c94c07c6ad4f8d8955332883471ae309d6667eee6a587c81117c857c70cf4595a45085fc20692dbfabb98fa98c7613247a8c28fc89eedd1d331f5b963db91898483097ca20290fddf402ac47c5c6b1ce92c3b1a272282e306dc0057353a7e0931ff676407cf0c757f8111d50c3293d6a639880efa79ba532d99cdb57a5d407698ef6598b6d368311ac7c8995bfddc941f4a5863c43452c474348ad7c5a0fcc084be49fa8d8e720e859e0b67351016df69ac64e0be54dc4dc1f79b1d0a9704598b8a18455d600268eb041297ae8ce6ad7ba34ed818a78dfbafdaec82f20d39c83329109c662b005b25a6de56bff1d254460e4cc137ca9db526352b1290714a78a8fa9b7109298361dd25f8a69b18e282926bff5e5d06f0c3b4a871ea9d01967fa7061ccom.v2ray.v2vpn"
)
# Dark VPN / V2Dark (FlyD) — live gem-panel only (no CDN/cache fallback).
DV_API_URL = "https://api.gem-panel.com/api/v1/apps/app-data"
DV_API_KEY = "fdef0f5e-9aba-43d2-b75b-e11baa8d7f99"
DV_APP_VERSION = "110.1"
DV_KEY_MATERIAL = """3082058930820371a00302010202150096643cf074b408fabfdb03ad4b2771a5d994565c300d06092a864886f70d01010b05003074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f69643020170d3233303533313037333835355a180f32303533303533313037333835355a3074310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307416e64726f69643110300e06035504031307416e64726f696430820222300d06092a864886f70d01010105000382020f003082020a0282020100a1070e353c122c9c4ce83f4a396931bc494c706a09f65b061a35dbea2df5445ef092e6b1f34182a74bf4f9ea96e02aa4e502b12d1ea03550acaaf92657d956d8ca595fa66c74868d9a2986de73276d97f7721822f567400a3441f3b1ff53796f8659f489eb60dc3ce21dacc67b7b16715da05f09ea5138768590d900868bd97b794ce909f16ae6f0df186c4ae693b71ecf4ba119e8312467605e2d759f49ce57b68dca390b57f2ad74966b00373ff5d1cc99dff9cdbe015e9be2c67460f5d1b91f6dc0cb0a43ec60296ded610caa25cbfadf8cfc5e0b29726c2aa2c797ae66b9654c26b951583bf6b9fac871d687067e23cfb002f00a4ce1ab95c3c0aba6627ecb531765dfe201bb608853c3e47527050ce0dba42d37de83d0d7af3b0bc9f7688cd413962b2c7d5ce222749c6bd2754df12b20a134702e1f972f2bab85ffde570c7b18dd407b603d2414838b4af627f55ade7630965ea8b0cbe361c5dbf307d14edc11fbaed17866d4f2f1e62988962d086c3a646fc7931abcf6539adc9899302cc9ff6c84c643bbb719907c93fba71990f6e57a2ac4ed5f497b4fb18f20046fd1089f2b800565ff0d8bd00d89e616ea999cacca9d77fee4c847278f5e0324588b3293a5135a0ba7287fd789d32782fad7d7bb1be6dc2197360e8cf7386fbb25f7560bd0cf625d3d42aca108e53d6fb7b8e7542ce2a08d37f9418351686bdcab0203010001a310300e300c0603551d13040530030101ff300d06092a864886f70d01010b050003820201000323b5200b8b71f2115dc3619d7235e145d069b6ef5400ee41eab5510fec53b458ff656511cb84fd67ec0862a5c4f25decaaa9d4e9ff0c99e769e87f2897bcb07ebbd3fd331df0f2daf1154a1070e7e2c793f9298dac26b2558fa961277dbf33e32f28e2d2a389b44574e23afc485731a9a6dcf353a5a322d7b22cba25d438176a2c50ea93cf55610b180e6596c2c7b376a391b73d22cf648b0ece469f979af295079e99b1453b26a0dd3522efeb807b64a24ea19d75de1702379efefe03fd3f681b053892e34bbbf449ad1f99604a67e1914685220d715803badc9897e9ca4016cbd632561907b17efd61b268e8b6dd7bdec137aa87350c88c5790d58f29df1bc704b55805525592a1ef76b3615ec26058ca8c3af302f81ad8dd82444a8980b992a8d29d52a113e4f0410f02c46707fddf3d707d43de5e22b85d578caaa62b4a73c34b4c261d9a6c879f6733b52a9a66808795681fa882e300342757cca249cae36c9fcc552f5acb4028c62f333f311ad74552a122ad66d1cfb0c48a2a70dd3799ccb9a1378fa4a9c37e04a3e1ef07f1855cc581f18200217e5df2daf1f41c79e12142213e169e22289f728f717018e78a500871a27fbbe6a897d79f569db96f699802029bd49e705fed41c90a9e1bf15c6abb0543766d96668508f9efa381e803e7985091cdd6e2f49e1b0b389c7fdfd93334e361539488ca266be1a874436com.dark.vpn.free"""
# Secret VPN / V2rayNet (FlyF) — cert SHA-256 must stay UPPERCASE for auth.
SV_APK_SHA256 = "87179CAE7B0C68EB9939D437BB4747CEBB24F19F232538749A16C04696BAAC3F"
SV_PACKAGE = "app.secretvpn.free"
SV_ADMOB = "ca-app-pub-1957678521576263~7067782716"
SV_ACTION = "refresh_servers"
SV_HMAC_SECRET = b"kiunniiokikkkkkkkkkkkkkkkkkkkkkk"
SV_AES_KEY_MATERIAL = b"MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2"
SV_AES_IV = b"TjWnZr4u7x!z%C*F"
# TopVPN / SupraVPN (FlyT)
TV_API_URL = "https://fxgoldensignals.com/TopVPN/v2/api/main.php"
TV_DECRYPT_PASSWORD = b"pXPWUjFm0hW612tav5Ez"
TV_PBKDF_ITERATIONS = 10000
TV_APP_VERSION = "555"
# ExoVPN (FlyExo) — primary + SecondURL fallback from last good payload
EXO_API_URLS = (
    "https://oxekinl.com/f887c412-f267-4014-8512-e72c88f0fdfd",
    "https://goglcdn.com/a4912c28-6fb5-43a9-8c20-22c0cdb15bfd",
)
EXO_API_URL = EXO_API_URLS[0]
EXO_ANSWER = "tfodogfxklkfanoxuyrskuvnx"
EXO_PRIME = int(
    "115792089237316195423570985008687907853269984665640564039457584007913129319283"
)
EXO_D_CONST = "aK9zP3LmX7qT2vR8bN5"
EXO_SEED = "hT5Kp9Qa"
EXO_DATE_XOR = 6510615555426900570
EXO_DATE_MOD = 1000000007
EXO_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
EXO_ALPHA_FROM = (
    "!@#$%^&*()-=_+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
EXO_ALPHA_TO = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+"
)
EXO_SHARE_PREFIXES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria://",
    "hysteria2://",
    "tuic://",
)
ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out" / "cfg.txt"
EXO_CACHE = ROOT / "cache" / "flyexo.txt"
FLYB_CACHE = ROOT / "cache" / "flyb.txt"
FLYD_ADS_OUT = ROOT / "cache" / "flyd_smart.txt"


def set_link_name(link: str, name: str) -> str:
    base = link.split("#", 1)[0].rstrip()
    if base.startswith("vmess://"):
        try:
            b64 = base[len("vmess://") :]
            pad = "=" * ((4 - len(b64) % 4) % 4)
            obj = json.loads(base64.b64decode(b64 + pad).decode("utf-8", errors="replace"))
            if isinstance(obj, dict):
                obj["ps"] = name
                new_b64 = base64.b64encode(
                    json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).decode("ascii")
                return f"vmess://{new_b64}#{name}"
        except Exception:
            pass
    return f"{base}#{name}"


def rename_links(links: list[str], prefix: str) -> list[str]:
    """Deduplicate link bases and rename them as prefix-1, prefix-2, ..."""
    seen: set[str] = set()
    unique: list[str] = []
    for link in links:
        base = link.split("#", 1)[0].rstrip()
        if not base or base in seen:
            continue
        seen.add(base)
        unique.append(base)
    return [set_link_name(link, f"{prefix}-{i}") for i, link in enumerate(unique, start=1)]


def http_get_json(url: str, extra: dict[str, str] | None = None, timeout: int = 25) -> dict:
    headers = dict(HEADERS)
    if extra:
        headers.update(extra)
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_links(text: str) -> list[str]:
    return re.findall(r"(?:vless|vmess|trojan|ss)://\S+", text)


def flyb_load_cache() -> list[str]:
    """Load last-known FlyB share links from cache file."""
    if not FLYB_CACHE.exists():
        return []
    links = []
    for line in FLYB_CACHE.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            links.append(s)
    return links


def flyb_save_cache(links: list[str]) -> None:
    """Persist FlyB links for use when Begzar live API is down."""
    FLYB_CACHE.parent.mkdir(parents=True, exist_ok=True)
    FLYB_CACHE.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8")


def begzar_integrity(device_id: str) -> str:
    """Build X-Begzar-Integrity = sha256_hex(cert|deviceId|vault)."""
    msg = f"{APK_CERT_SHA256}|{device_id}|{VAULT_SIGN_INFO}".encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def begzar_sign(method: str, sign_path: str, ts: str, nonce: str, body: bytes, secret: bytes, device_id: str) -> str:
    """Port of native signRequest: HMAC(signing_key, METHOD\npath\nts\nnonce\nbodyhash)."""
    signing_key = hmac.new(
        secret,
        f"{APK_CERT_SHA256}|{device_id}|{VAULT_SIGN_INFO}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{sign_path}\n{ts}\n{nonce}\n{body_hash}".encode("utf-8")
    return hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()


def begzar_http(path: str, body: bytes | None = b"{}", extra: dict[str, str] | None = None, method: str = "POST", timeout: int = 30) -> tuple[int, bytes]:
    """POST/GET engage.begweb.com and return (status, raw body)."""
    headers = dict(HEADERS)
    if extra:
        headers.update(extra)
    if method == "GET":
        headers.pop("Content-Type", None)
        data = None
    else:
        data = body if body is not None else b""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(API_BASE + path, data=data, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def begzar_register() -> str:
    """Register free Android session and return session_token."""
    status, raw = begzar_http(REGISTER_PATH, b"{}")
    if status != 200:
        raise RuntimeError(f"register HTTP {status}: {raw[:200]!r}")
    data = json.loads(raw.decode("utf-8"))
    token = data.get("session_token")
    if not token:
        raise RuntimeError(f"no session_token: {data}")
    return token


def begzar_decrypt_bgz4(blob: bytes) -> str:
    """Decrypt BGZ4 AES-GCM subscription envelope into UTF-8 text."""
    if blob.lstrip().startswith((b"{", b"[")):
        return blob.decode("utf-8", errors="replace")
    if not blob.startswith(BGZ4_MAGIC) or len(blob) < 4 + 12 + 16:
        raise RuntimeError(f"unexpected begzar payload prefix={blob[:12]!r}")
    aes = AESGCM(BGZ4_KEY)
    candidates = [(blob[4:16], blob[16:])]
    if len(blob) > 33:
        candidates.append((blob[5:17], blob[17:]))
    for nonce, ct in candidates:
        if len(nonce) != 12 or len(ct) < 16:
            continue
        for aad in (None, BGZ4_MAGIC, blob[:5]):
            try:
                return aes.decrypt(nonce, ct, aad).decode("utf-8", errors="replace")
            except Exception:
                continue
    raise RuntimeError("BGZ4 decrypt failed")


def begzar_fetch_live() -> list[str]:
    """Fetch Begzar servers via API v4 signed subscription endpoint."""
    token = begzar_register()
    secret = base64.b64decode(token)
    device_id = str(uuid.uuid4())
    body = b"{}"
    nonce = secrets.token_hex(16)
    ts = str(int(time.time()))
    headers = {
        "X-Begzar-Device-Id": device_id,
        "X-Begzar-Session-Key": token,
        "X-Begzar-Nonce": nonce,
        "X-Begzar-Timestamp": ts,
        "X-Begzar-Integrity": begzar_integrity(device_id),
        "X-Begzar-Signature": begzar_sign("POST", SIGN_PATH, ts, nonce, body, secret, device_id),
    }
    status, raw = begzar_http(FETCH_PATH, body, headers)
    if status != 200 and not raw.startswith(BGZ4_MAGIC):
        raise RuntimeError(f"fetch HTTP {status}: {raw[:240]!r}")
    text = begzar_decrypt_bgz4(raw)
    links = rename_links(extract_links(text), "FlyB")
    if not links:
        raise RuntimeError("begzar v4 returned no share links")
    return links


def fetch_flyb_links() -> list[str]:
    """Fetch Begzar configs as FlyB-*; fall back to cache if live API fails."""
    errors: list[str] = []
    try:
        links = begzar_fetch_live()
        flyb_save_cache(links)
        return links
    except Exception as exc:
        errors.append(str(exc))
    cached = flyb_load_cache()
    if cached:
        print(
            f"FlyB using cache ({len(cached)} links); live failed: "
            + "; ".join(errors)[:400],
            file=sys.stderr,
        )
        return rename_links(cached, "FlyB")
    raise RuntimeError("; ".join(errors) if errors else "begzar fetch failed")


def fetch_v2_wrapper() -> dict:
    """Fetch encrypted V2VPN app-data from primary API or public fallbacks."""
    sources = [
        (
            V2_API_URL,
            {
                "User-Agent": "okhttp/4.12.0",
                "authorization": f"ApiKey {V2_API_KEY}",
                "v": V2_APP_VERSION,
            },
        ),
        (V2_RAW_URL, {"User-Agent": "okhttp/4.12.0"}),
        (V2_GITLAB_URL, {"User-Agent": "okhttp/4.12.0"}),
    ]
    errors: list[str] = []
    for url, headers in sources:
        try:
            return http_get_json(url, headers, timeout=45)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError(" | ".join(errors))


def decrypt_v2_payload(wrapper: dict) -> dict:
    """Decrypt V2VPN payload with AES-CTR then gzip, matching the Android client."""
    encoded = wrapper.get("data")
    if not encoded:
        raise ValueError("V2VPN response missing encrypted data")
    payload = base64.b64decode(encoded)
    if len(payload) <= 16:
        raise ValueError("V2VPN encrypted payload too short")
    iv = payload[:16]
    ciphertext = payload[16:]
    key = hashlib.sha256(V2_KEY_MATERIAL.encode("utf-8")).digest()
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(gzip.decompress(plain).decode("utf-8"))


def build_vless_link(outbound: dict) -> str | None:
    """Build one vless:// URI from an Xray vless outbound."""
    if outbound.get("protocol") != "vless":
        return None
    vnext_list = outbound.get("settings", {}).get("vnext", [])
    if not vnext_list:
        return None
    vnext = vnext_list[0]
    users = vnext.get("users", [])
    if not users:
        return None
    user = users[0]
    stream = outbound.get("streamSettings", {})
    ws = stream.get("wsSettings", {})
    tls = stream.get("tlsSettings", {})
    host = ws.get("headers", {}).get("Host") or ""
    query = {
        "encryption": "none",
        "security": stream.get("security", "none"),
        "type": stream.get("network", "tcp"),
        "path": ws.get("path", ""),
        "host": host,
        "sni": tls.get("serverName", ""),
        "fp": tls.get("fingerprint", ""),
    }
    return (
        f"vless://{user.get('id')}@{vnext.get('address')}:{vnext.get('port')}"
        f"?{urllib.parse.urlencode(query)}"
    )


def fetch_flyv_links() -> list[str]:
    """Fetch V2VPN profiles and rename them as FlyV-*."""
    wrapper = fetch_v2_wrapper()
    app_data = decrypt_v2_payload(wrapper)
    links: list[str] = []
    for section in ("normal", "smart"):
        for profile in app_data.get("configs", {}).get(section, []):
            cfg = json.loads(profile["config"])
            for outbound in cfg.get("outbounds", []):
                link = build_vless_link(outbound)
                if link:
                    links.append(link)
    return rename_links(links, "FlyV")


def fetch_dv_wrapper() -> dict:
    """Fetch encrypted DarkVPN app-data from live gem-panel only."""
    return http_get_json(
        DV_API_URL,
        {
            "User-Agent": "okhttp/4.12.0",
            "authorization": f"ApiKey {DV_API_KEY}",
            "v": DV_APP_VERSION,
        },
        timeout=45,
    )


def decrypt_dv_payload(wrapper: dict) -> dict:
    """Decrypt DarkVPN payload with AES-CTR then gzip/raw JSON."""
    encoded = wrapper.get("data")
    if not encoded:
        raise ValueError("DarkVPN response missing encrypted data")
    payload = base64.b64decode(encoded)
    if len(payload) <= 16:
        raise ValueError("DarkVPN encrypted payload too short")
    iv = payload[:16]
    ciphertext = payload[16:]
    key = hashlib.sha256(DV_KEY_MATERIAL.encode("utf-8")).digest()
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        return json.loads(gzip.decompress(plain).decode("utf-8"))
    except Exception:
        return json.loads(plain.decode("utf-8"))


def extract_flyd_config_link(config_value) -> str | None:
    """Extract a share URI from DarkVPN config (URI first, else Xray JSON)."""
    if not isinstance(config_value, str):
        return None
    value = config_value.strip()
    if not value:
        return None
    for scheme in ("vless://", "vmess://", "trojan://", "ss://"):
        if value.startswith(scheme):
            return value
    if value.startswith("{"):
        try:
            cfg = json.loads(value)
        except json.JSONDecodeError:
            return None
        for outbound in cfg.get("outbounds", []):
            link = build_vless_link(outbound)
            if link:
                return link
    return None


def extract_flyd_section_links(app_data: dict, section: str) -> list[str]:
    """Collect share links from one DarkVPN configs section (normal or smart)."""
    links: list[str] = []
    for profile in app_data.get("configs", {}).get(section, []) or []:
        cfg_val = profile.get("config") if isinstance(profile, dict) else profile
        link = extract_flyd_config_link(cfg_val)
        if link:
            links.append(link)
    return links


def save_flyd_ads_snapshot(links: list[str]) -> int:
    """Overwrite DarkVPN smart/ads snapshot from this live fetch (never read back)."""
    renamed = rename_links(links, "FlyD-Ad")
    FLYD_ADS_OUT.parent.mkdir(parents=True, exist_ok=True)
    FLYD_ADS_OUT.write_text(
        "\n".join(renamed) + ("\n" if renamed else ""),
        encoding="utf-8",
    )
    return len(renamed)


def fetch_flyd_links() -> tuple[list[str], int]:
    """Fetch live DarkVPN normal for cfg; write smart/ads snapshot separately."""
    wrapper = fetch_dv_wrapper()
    app_data = decrypt_dv_payload(wrapper)
    normal = extract_flyd_section_links(app_data, "normal")
    smart = extract_flyd_section_links(app_data, "smart")
    ads_count = save_flyd_ads_snapshot(smart)
    return rename_links(normal, "FlyD"), ads_count


def fold_domain_id(value: str) -> str:
    """Fold SHA-256 three times by half-XOR down to 4 bytes (8 hex chars)."""
    digest = bytearray(hashlib.sha256(value.encode("utf-8")).digest())
    for step in range(1, 4):
        half = 32 // (2 ** step)
        out = bytearray(half)
        for i in range(half):
            out[i] = digest[i] ^ digest[i + half]
        digest = out
    return bytes(digest).hex()


def build_secretvpn_signature(sha_hex: str, kss: list[int], rts: list[int]) -> str:
    """Build 32-char key field from APK cert sha hex using kss/rts indices."""
    chars: list[str] = []
    for i in range(16):
        i2 = (i + rts[i]) % 16
        chars.append(sha_hex[kss[i]])
        chars.append(sha_hex[kss[i2]])
    return "".join(chars)


def make_secretvpn_token(timestamp: int, nonce: str) -> str:
    """Build two-stage HMAC-SHA256 token for Secret VPN check.token."""
    pre = f"{SV_PACKAGE}\n{SV_ADMOB}\n{SV_APK_SHA256}"
    full = f"{SV_PACKAGE}\n{SV_ADMOB}\n{SV_APK_SHA256}\n{SV_ACTION}\n{timestamp}\n{nonce}"
    stage1 = hmac.new(SV_HMAC_SECRET, pre.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.new(stage1.encode("utf-8"), full.encode("utf-8"), hashlib.sha256).hexdigest()


def decrypt_secretvpn_field(b64: str) -> bytes:
    """Decrypt Secret VPN API field with AES-256-CFB8."""
    key = hashlib.md5(SV_AES_KEY_MATERIAL).hexdigest().encode("ascii")
    decryptor = Cipher(algorithms.AES(key), AesCFB8(SV_AES_IV)).decryptor()
    return decryptor.update(base64.b64decode(b64)) + decryptor.finalize()


def fetch_flyf_links() -> list[str]:
    """Fetch Secret VPN free servers and rename them as FlyF-*."""
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    kss = [random.randrange(64) for _ in range(16)]
    rts = [random.randrange(0xB237) for _ in range(16)]
    vld = 17 * random.randrange(0x35EC011) + 17
    body = {
        "kss": kss,
        "rts": rts,
        "key": build_secretvpn_signature(SV_APK_SHA256, kss, rts),
        "vld": vld,
        "check": {
            "action": SV_ACTION,
            "timestamp": timestamp,
            "nonce": nonce,
            "token": make_secretvpn_token(timestamp, nonce),
        },
    }
    url = f"https://vant{fold_domain_id('1')}.xyz/client/api/v1/servers"
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw_body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-App-Version": "1.0.0",
        },
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if not payload.get("successful"):
        raise RuntimeError(f"secretvpn failed: {payload}")
    servers = json.loads(decrypt_secretvpn_field(payload["srv"]).decode("utf-8"))
    links: list[str] = []
    for country in servers:
        for server in country.get("servers") or []:
            link = urllib.parse.unquote(server.get("config") or "").strip()
            if link:
                links.append(link)
    return rename_links(links, "FlyF")


def decrypt_topvpn_payload(blob: str) -> str:
    """Decrypt TopVPN API body: Base64 -> salt|iv|ct -> PBKDF2-AES-CBC."""
    data = base64.b64decode(blob.strip())
    if len(data) < 32:
        raise ValueError("topvpn encrypted payload too short")
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=TV_PBKDF_ITERATIONS,
        backend=default_backend(),
    ).derive(TV_DECRYPT_PASSWORD)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode("utf-8")


def extract_topvpn_links(payload: dict) -> list[str]:
    """Collect unique share links from TopVPN defaultServer and Connection_Config."""
    links: list[str] = []
    default_cfg = (payload.get("defaultServer") or {}).get("config")
    if isinstance(default_cfg, str) and "://" in default_cfg:
        links.append(default_cfg)
    for server in payload.get("servers") or []:
        cfg_map = server.get("Connection_Config") or {}
        if isinstance(cfg_map, dict):
            for value in cfg_map.values():
                if isinstance(value, str) and "://" in value:
                    links.append(value)
        blob = json.dumps(server, ensure_ascii=False)
        links.extend(re.findall(r"(?:vless|vmess|trojan|ss)://\S+", blob))
    return links


def fetch_flyt_links() -> list[str]:
    """Fetch TopVPN free servers and rename them as FlyT-*."""
    device = uuid.uuid4().hex
    query = (
        f"access_token=&GetServerList=&defualtServerID=&device_id={device}"
        f"&isp=MTN&version={TV_APP_VERSION}&isPartnership=FALSE"
        f"&t={int(time.time() * 1000)}"
    )
    req = urllib.request.Request(
        f"{TV_API_URL}?{query}",
        headers={
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=40, context=ctx) as resp:
        text = resp.read().decode("utf-8", errors="replace").strip()
    if text.startswith("{") and '"status"' in text[:80]:
        raise RuntimeError(f"topvpn rejected: {text}")
    payload = json.loads(decrypt_topvpn_payload(text))
    return rename_links(extract_topvpn_links(payload), "FlyT")


def exo_xor_strings(a: str, b: str) -> str:
    """XOR two strings cyclically, like ExoVPN X.Y.D.a."""
    return "".join(
        chr(ord(a[i % len(a)]) ^ ord(b[i % len(b)]))
        for i in range(max(len(a), len(b)))
    )


def exo_checksum(text: str) -> str:
    """Compute ExoVPN request check header: sum((i+1)*char)."""
    return str(sum((i + 1) * ord(ch) for i, ch in enumerate(text)))


def exo_encrypt_body(plaintext: str, check: str) -> str:
    """Encrypt ExoVPN POST body (port of packed X.Y.D.b)."""
    day = datetime.now(timezone.utc).day
    day_hex = hashlib.sha256(str(day).encode("utf-8")).hexdigest()
    key_seed = exo_xor_strings(exo_xor_strings(check, day_hex), EXO_D_CONST)
    key = hashlib.sha256(key_seed.encode("utf-8")).digest()[:16]
    pad_len = day + 100
    stream = bytes(random.randrange(256) for _ in range(pad_len))
    filler = bytes(random.randrange(256) for _ in range(100))
    raw = plaintext.encode("utf-8")
    xored = bytes(raw[i] ^ stream[i % pad_len] for i in range(len(raw)))
    interleaved = bytearray(len(raw) * 2)
    payload_i = 0
    for i in range(len(interleaved)):
        if i % 2 != 0 or payload_i >= len(raw):
            interleaved[i] = filler[i % 100]
        else:
            interleaved[i] = xored[payload_i]
            payload_i += 1
    blob = stream + bytes(interleaved)
    padder = PKCS7(128).padder()
    padded = padder.update(blob) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    check_bytes = check.encode("utf-8")
    mixed = bytes(
        check_bytes[i % len(check_bytes)] ^ encrypted[i] for i in range(len(encrypted))
    )
    mixed = bytes(b ^ len(check) for b in mixed)
    filler2 = bytes(random.randrange(256) for _ in range(100))
    out = bytearray(len(mixed) * 2)
    payload_i = 0
    for i in range(len(out)):
        if i % 2 != 0 or payload_i >= len(mixed):
            out[i] = filler2[i % 100]
        else:
            out[i] = mixed[payload_i]
            payload_i += 1
    for i in range(len(out)):
        j = i + 8
        if j < len(out):
            out[i], out[j] = out[j], out[i]
    return base64.b64encode(bytes(out)).decode("ascii")


def exo_date_aes_key() -> bytes:
    """Build 16-byte AES key from GMT yyyyMMdd + seed (X.Y.A0)."""
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    val = str((int(date) ^ EXO_DATE_XOR) % EXO_DATE_MOD)
    out: list[str] = []
    i_seed = 0
    i_val = 0
    while i_seed < len(EXO_SEED) or i_val < len(val):
        if i_seed < len(EXO_SEED):
            out.append(EXO_SEED[i_seed])
            i_seed += 1
        if i_val < len(val):
            out.append(val[i_val])
            i_val += 1
    key = "".join(out)
    if len(key) > 16:
        key = key[:16]
    elif len(key) < 16:
        key = key.ljust(16, "0")
    return key.encode("utf-8")


def exo_transform_chars(chars: list[str]) -> None:
    """Apply ExoVPN alphabet map, XOR 'Z', and deterministic shuffle in-place."""
    for i, ch in enumerate(chars):
        idx = EXO_ALPHA_FROM.find(ch)
        if idx >= 0:
            chars[i] = EXO_ALPHA_TO[idx]
    for i in range(len(chars)):
        chars[i] = chr(ord(chars[i]) ^ ord("Z"))
    length = len(chars) - 1
    while length >= 0:
        j = ((length * 7) + 3) % len(chars)
        chars[length], chars[j] = chars[j], chars[length]
        length -= 1


def exo_decrypt_data(cipher_b64: str) -> str:
    """Decrypt ExoVPN response data field (port of packed X.Y.A0.a)."""
    key = exo_date_aes_key()
    chars = list(base64.b64decode(cipher_b64).decode("latin-1"))
    exo_transform_chars(chars)
    ciphertext = base64.b64decode("".join(chars))
    decryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    chars2 = list(plain.decode("utf-8"))
    exo_transform_chars(chars2)
    return "".join(chars2)


def exo_build_request_json(api_url: str = EXO_API_URL) -> str:
    """Build ExoVPN signed JSON body with Nonce/key1/key2 metadata."""
    nonce = str(uuid.uuid4())

    def rand_token() -> str:
        n = max(10, random.randint(0, 59))
        return "".join(EXO_ALPHA[random.randrange(len(EXO_ALPHA))] for _ in range(n))

    obj: dict = {}
    obj[rand_token()] = rand_token()
    obj["Nonce"] = nonce
    obj["VersionName"] = "1.0"
    obj["VersionCode"] = "20260426"
    now = datetime.now(timezone.utc)
    hour_bytes = struct.pack(">i", now.hour)
    minute_bytes = struct.pack(">i", now.minute)
    nonce_bytes = nonce.encode("utf-8")
    size = max(len(nonce_bytes), len(hour_bytes))
    matrix = bytearray()
    for i in range(size):
        for j in range(size):
            matrix.append(
                (nonce_bytes[i % len(nonce_bytes)] * hour_bytes[j % len(hour_bytes)])
                & 255
            )
    obj["key1"] = base64.b64encode(bytes(matrix)).decode("ascii")
    base = int.from_bytes(nonce_bytes, "big", signed=True)
    exp = int.from_bytes(minute_bytes, "big", signed=True)
    obj["key2"] = base64.b64encode(
        str(pow(base, exp, EXO_PRIME)).encode("utf-8")
    ).decode("ascii")
    obj["key3"] = ""
    obj["key4"] = "---"
    obj["key5"] = "unknown"
    obj["key6"] = "google"
    obj["key7"] = "sdk_gphone64_arm64"
    obj["key9"] = api_url
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def extract_exo_share_links(payload: dict) -> list[str]:
    """Collect share URIs from ExoVPN Configs_app / Configs_sp / Configs_vip."""
    links: list[str] = []
    for section in ("Configs_app", "Configs_sp", "Configs_vip"):
        for block in payload.get(section) or []:
            items = (
                block.get("config_items")
                if isinstance(block, dict) and "config_items" in block
                else ([block] if isinstance(block, dict) else [])
            )
            for item in items or []:
                content = (item or {}).get("config_content") or ""
                if isinstance(content, str) and content.strip().lower().startswith(
                    EXO_SHARE_PREFIXES
                ):
                    links.append(content.strip())
    return links


def exo_doh_a_records(host: str) -> list[str]:
    """Resolve all A records via Cloudflare DoH to avoid local fake-IP DNS."""
    req = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?name={host}&type=A",
        headers={"Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        ips: list[str] = []
        for item in data.get("Answer") or []:
            if item.get("type") == 1 and item.get("data"):
                ip = str(item["data"])
                if ip not in ips:
                    ips.append(ip)
        return ips
    except Exception:
        return []


def exo_doh_a(host: str) -> str | None:
    """Resolve first A record via Cloudflare DoH."""
    ips = exo_doh_a_records(host)
    return ips[0] if ips else None


def _exo_parse_api_body(raw: bytes | str) -> dict:
    """Parse ExoVPN API body; reject empty/HTML/Cloudflare error pages."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else raw
    text = (text or "").strip()
    if not text:
        raise RuntimeError("exovpn empty response")
    if text[0] not in "{[":
        raise RuntimeError(f"exovpn non-json response: {text[:120]!r}")
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise RuntimeError("exovpn response is not an object")
    return parsed


def exo_post_encrypted(encrypted: str, check: str, api_url: str = EXO_API_URL) -> dict:
    """POST encrypted ExoVPN body; try urllib then curl+DoH across all A records."""
    import subprocess
    import tempfile

    token = base64.b64encode(EXO_ANSWER.encode("utf-8")).decode("ascii")
    headers = {
        "token": token,
        "lang": "en",
        "check": check,
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "okhttp/4.12.0",
        "Accept-Encoding": "identity",
    }
    body = encrypted.encode("utf-8")
    errors: list[str] = []
    req = urllib.request.Request(api_url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
            return _exo_parse_api_body(resp.read())
    except Exception as exc:
        errors.append(f"urllib:{exc}")
    host = urllib.parse.urlparse(api_url).hostname or "oxekinl.com"
    ips = exo_doh_a_records(host)
    if not ips:
        raise RuntimeError("; ".join(errors) if errors else f"DoH failed for {host}")
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(encrypted)
        tmp_path = tmp.name
    try:
        for ip in ips:
            cmd = [
                "curl",
                "-sS",
                "--http1.1",
                "--resolve",
                f"{host}:443:{ip}",
                "-X",
                "POST",
                api_url,
                "-H",
                f"token: {token}",
                "-H",
                "lang: en",
                "-H",
                f"check: {check}",
                "-H",
                "Content-Type: application/json; charset=utf-8",
                "-H",
                "User-Agent: okhttp/4.12.0",
                "-H",
                "Accept-Encoding: identity",
                "--data-binary",
                f"@{tmp_path}",
                "--max-time",
                "12",
                "-w",
                "\n__HTTP__:%{http_code}",
            ]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                errors.append(f"curl/{ip}:exit{exc.returncode}")
                continue
            text = out.decode("utf-8", errors="replace")
            if "\n__HTTP__:" in text:
                body_text, _, code = text.rpartition("\n__HTTP__:")
                code = code.strip()
            else:
                body_text, code = text, "?"
            if code not in ("200", "201"):
                errors.append(f"curl/{ip}:http{code}:{body_text[:80]!r}")
                continue
            try:
                return _exo_parse_api_body(body_text)
            except Exception as exc:
                errors.append(f"curl/{ip}:{exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    raise RuntimeError("; ".join(errors) if errors else "exovpn post failed")


def exo_load_cache() -> list[str]:
    """Load last-known FlyExo share links from cache file."""
    if not EXO_CACHE.exists():
        return []
    links = []
    for line in EXO_CACHE.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            links.append(s)
    return links


def exo_save_cache(links: list[str]) -> None:
    """Persist FlyExo links for use when upstream API is down."""
    EXO_CACHE.parent.mkdir(parents=True, exist_ok=True)
    EXO_CACHE.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8")


def fetch_flyexo_links() -> list[str]:
    """Fetch ExoVPN free share links; fall back to cache if upstream is down."""
    errors: list[str] = []
    for api_url in EXO_API_URLS:
        try:
            body_json = exo_build_request_json(api_url)
            check = exo_checksum(body_json)
            encrypted = exo_encrypt_body(body_json, check)
            parsed = exo_post_encrypted(encrypted, check, api_url)
            if parsed.get("status") != 200 or not parsed.get("data"):
                raise RuntimeError(f"exovpn rejected: {json.dumps(parsed)[:300]}")
            payload = json.loads(exo_decrypt_data(parsed["data"]))
            links = rename_links(extract_exo_share_links(payload), "FlyExo")
            if links:
                exo_save_cache(links)
                second = payload.get("SecondURL")
                if isinstance(second, str) and second.startswith("http") and second not in EXO_API_URLS:
                    print(f"FlyExo hint SecondURL={second}", file=sys.stderr)
                return links
            errors.append(f"{api_url}:no share links")
        except Exception as exc:
            errors.append(f"{api_url}:{exc}")
    cached = exo_load_cache()
    if cached:
        print(
            f"FlyExo using cache ({len(cached)} links); live failed: "
            + "; ".join(errors)[:400],
            file=sys.stderr,
        )
        return cached
    raise RuntimeError("; ".join(errors) if errors else "exovpn fetch failed")

def telegram_chat_ids() -> list[str]:
    """Collect unique Telegram chat IDs from TELEGRAM_CHAT_ID (comma-separated)."""
    raw = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    ids: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        chat_id = part.strip()
        if not chat_id or chat_id in seen:
            continue
        seen.add(chat_id)
        ids.append(chat_id)
    return ids


def notify_telegram(text: str) -> None:
    """Send a Telegram message to every configured chat id."""
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_ids = telegram_chat_ids()
    if not token or not chat_ids:
        print("telegram skipped: missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for chat_id in chat_ids:
        body = urllib.parse.urlencode(
            {
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": "true",
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            if not data.get("ok"):
                print(f"telegram api error chat_id={chat_id}: {raw[:300]}")
                continue
            print(
                f"telegram sent chat_id={chat_id} "
                f"message_id={data.get('result', {}).get('message_id')}"
            )
        except Exception as exc:
            print(f"telegram send failed chat_id={chat_id}: {exc}")


def main() -> int:
    """Fetch FlyB + FlyV + FlyF + FlyT + FlyExo + FlyD configs into one subscription file and notify Telegram."""
    errors: list[str] = []
    flyb: list[str] = []
    flyv: list[str] = []
    flyf: list[str] = []
    flyt: list[str] = []
    flyexo: list[str] = []
    flyd: list[str] = []
    flyd_ads = 0
    try:
        flyb = fetch_flyb_links()
    except Exception as exc:
        errors.append(f"FlyB · Begzar: {exc}")
        print(f"FlyB failed: {exc}", file=sys.stderr)
    try:
        flyv = fetch_flyv_links()
    except Exception as exc:
        errors.append(f"FlyV · V2VPN: {exc}")
        print(f"FlyV failed: {exc}", file=sys.stderr)
    try:
        flyf = fetch_flyf_links()
    except Exception as exc:
        errors.append(f"FlyF · Secret VPN: {exc}")
        print(f"FlyF failed: {exc}", file=sys.stderr)
    try:
        flyt = fetch_flyt_links()
    except Exception as exc:
        errors.append(f"FlyT · TopVPN: {exc}")
        print(f"FlyT failed: {exc}", file=sys.stderr)
    try:
        flyexo = fetch_flyexo_links()
    except Exception as exc:
        errors.append(f"FlyExo · ExoVPN: {exc}")
        print(f"FlyExo failed: {exc}", file=sys.stderr)
    try:
        flyd, flyd_ads = fetch_flyd_links()
    except Exception as exc:
        errors.append(f"FlyD · DarkVPN: {exc}")
        print(f"FlyD failed: {exc}", file=sys.stderr)
    links = flyb + flyv + flyf + flyt + flyexo + flyd
    if not links:
        raise RuntimeError("; ".join(errors) if errors else "no links")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    print(
        f"ok flyb={len(flyb)} flyv={len(flyv)} flyf={len(flyf)} flyt={len(flyt)} "
        f"flyexo={len(flyexo)} flyd={len(flyd)} flyd_ads={flyd_ads} "
        f"total={len(links)} path={OUT}"
    )
    msg = (
        f"✅ x7k sync OK\n"
        f"FlyB · Begzar: {len(flyb)}\n"
        f"FlyV · V2VPN: {len(flyv)}\n"
        f"FlyF · Secret VPN: {len(flyf)}\n"
        f"FlyT · TopVPN: {len(flyt)}\n"
        f"FlyExo · ExoVPN: {len(flyexo)}\n"
        f"FlyD · DarkVPN: {len(flyd)} (ads: {flyd_ads})\n"
        f"total: {len(links)}"
    )
    if errors:
        msg += "\n⚠️ " + "; ".join(errors)
    notify_telegram(msg)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        notify_telegram(f"❌ x7k sync FAILED\n{exc}")
        raise SystemExit(1)
