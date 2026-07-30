#!/usr/bin/env python3
"""Remote config sync: Begzar (FlyB) + V2VPN (FlyV) + SecretVPN (FlyF) + TopVPN (FlyT) + ExoVPN (FlyExo)."""

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
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
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
INIT_URL = f"{API_BASE}/api/v3/init/android"
DATA_URL_TMPL = f"{API_BASE}/api/v3/data/{{key}}"
TOTP_SALT = b"BegzarApp2025SecretSaltForTOTP"
HEADERS = {
    "User-Agent": "BegzarVPN",
    "Accept": "application/json",
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
# ExoVPN (FlyExo)
EXO_API_URL = "https://oxekinl.com/f887c412-f267-4014-8512-e72c88f0fdfd"
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


def totp(secret: bytes, digits: int = 6, step: int = 30) -> str:
    counter = int(time.time()) // step
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | digest[offset + 1] << 16
        | digest[offset + 2] << 8
        | digest[offset + 3]
    ) % (10**digits)
    return f"{code:0{digits}d}"


def fetch_key() -> str:
    data = http_get_json(INIT_URL)
    key = data.get("key")
    if not key:
        raise RuntimeError(f"no key in init: {data}")
    return key


def fetch_payload(key: str) -> dict:
    url = DATA_URL_TMPL.format(key=urllib.parse.quote(key, safe=""))
    secret = hashlib.sha256(key.encode("utf-8") + TOTP_SALT).digest()[:16]
    data = http_get_json(url, {"X-TOTP-Code": totp(secret)})
    if not data.get("status"):
        raise RuntimeError(f"data failed: {data}")
    inner = data.get("data") or {}
    for field in ("secure", "x1", "x2"):
        if field not in inner:
            raise RuntimeError(f"missing {field}")
    return data


def decrypt(key: str, secure: str, x1: str, x2: str) -> str:
    plain = ChaCha20Poly1305(base64.b64decode(key)).decrypt(
        base64.b64decode(x1),
        base64.b64decode(secure) + base64.b64decode(x2),
        None,
    )
    return plain.decode("utf-8")


def extract_links(text: str) -> list[str]:
    return re.findall(r"(?:vless|vmess|trojan|ss)://\S+", text)


def fetch_flyb_links() -> list[str]:
    """Fetch Begzar configs and rename them as FlyB-*."""
    key = fetch_key()
    payload = fetch_payload(key)
    inner = payload["data"]
    text = decrypt(key, inner["secure"], inner["x1"], inner["x2"])
    return rename_links(extract_links(text), "FlyB")


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


def exo_build_request_json() -> str:
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
    obj["key9"] = EXO_API_URL
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


def exo_doh_a(host: str) -> str | None:
    """Resolve A record via Cloudflare DoH to avoid local fake-IP DNS."""
    req = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?name={host}&type=A",
        headers={"Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        for item in data.get("Answer") or []:
            if item.get("type") == 1 and item.get("data"):
                return str(item["data"])
    except Exception:
        return None
    return None


def exo_post_encrypted(encrypted: str, check: str) -> dict:
    """POST encrypted ExoVPN body; fall back to curl+DoH when local DNS is poisoned."""
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
    req = urllib.request.Request(EXO_API_URL, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=45, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)
    except Exception as primary_exc:
        host = urllib.parse.urlparse(EXO_API_URL).hostname or "oxekinl.com"
        ip = exo_doh_a(host)
        if not ip:
            raise primary_exc
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(encrypted)
            tmp_path = tmp.name
        try:
            cmd = [
                "curl",
                "-sS",
                "--http1.1",
                "--resolve",
                f"{host}:443:{ip}",
                "-X",
                "POST",
                EXO_API_URL,
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
                "--data-binary",
                f"@{tmp_path}",
                "--max-time",
                "45",
            ]
            out = subprocess.check_output(cmd)
            return json.loads(out.decode("utf-8", errors="replace"))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def fetch_flyexo_links() -> list[str]:
    """Fetch ExoVPN free share links and rename them as FlyExo-*."""
    body_json = exo_build_request_json()
    check = exo_checksum(body_json)
    encrypted = exo_encrypt_body(body_json, check)
    parsed = exo_post_encrypted(encrypted, check)
    if parsed.get("status") != 200 or not parsed.get("data"):
        raise RuntimeError(f"exovpn rejected: {json.dumps(parsed)[:300]}")
    payload = json.loads(exo_decrypt_data(parsed["data"]))
    return rename_links(extract_exo_share_links(payload), "FlyExo")


def notify_telegram(text: str) -> None:
    """Send a Telegram message when bot token and chat id env vars are set."""
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        print("telegram skipped: missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
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
            print(f"telegram api error: {raw[:300]}")
            return
        print(f"telegram sent message_id={data.get('result', {}).get('message_id')}")
    except Exception as exc:
        print(f"telegram send failed: {exc}")


def main() -> int:
    """Fetch FlyB + FlyV + FlyF + FlyT + FlyExo configs into one subscription file and notify Telegram."""
    errors: list[str] = []
    flyb: list[str] = []
    flyv: list[str] = []
    flyf: list[str] = []
    flyt: list[str] = []
    flyexo: list[str] = []
    try:
        flyb = fetch_flyb_links()
    except Exception as exc:
        errors.append(f"FlyB: {exc}")
        print(f"FlyB failed: {exc}", file=sys.stderr)
    try:
        flyv = fetch_flyv_links()
    except Exception as exc:
        errors.append(f"FlyV: {exc}")
        print(f"FlyV failed: {exc}", file=sys.stderr)
    try:
        flyf = fetch_flyf_links()
    except Exception as exc:
        errors.append(f"FlyF: {exc}")
        print(f"FlyF failed: {exc}", file=sys.stderr)
    try:
        flyt = fetch_flyt_links()
    except Exception as exc:
        errors.append(f"FlyT: {exc}")
        print(f"FlyT failed: {exc}", file=sys.stderr)
    try:
        flyexo = fetch_flyexo_links()
    except Exception as exc:
        errors.append(f"FlyExo: {exc}")
        print(f"FlyExo failed: {exc}", file=sys.stderr)
    links = flyb + flyv + flyf + flyt + flyexo
    if not links:
        raise RuntimeError("; ".join(errors) if errors else "no links")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    print(
        f"ok flyb={len(flyb)} flyv={len(flyv)} flyf={len(flyf)} flyt={len(flyt)} "
        f"flyexo={len(flyexo)} total={len(links)} path={OUT}"
    )
    msg = (
        f"✅ x7k sync OK\nFlyB: {len(flyb)}\nFlyV: {len(flyv)}\n"
        f"FlyF: {len(flyf)}\nFlyT: {len(flyt)}\nFlyExo: {len(flyexo)}\n"
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
