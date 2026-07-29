#!/usr/bin/env python3
"""Remote config sync: Begzar (FlyB) + V2VPN (FlyV) + SecretVPN (FlyF) + TopVPN (FlyT)."""

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
    """Fetch FlyB + FlyV + FlyF + FlyT configs into one subscription file and notify Telegram."""
    errors: list[str] = []
    flyb: list[str] = []
    flyv: list[str] = []
    flyf: list[str] = []
    flyt: list[str] = []
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
    links = flyb + flyv + flyf + flyt
    if not links:
        raise RuntimeError("; ".join(errors) if errors else "no links")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    print(
        f"ok flyb={len(flyb)} flyv={len(flyv)} flyf={len(flyf)} flyt={len(flyt)} "
        f"total={len(links)} path={OUT}"
    )
    msg = (
        f"✅ x7k sync OK\nFlyB: {len(flyb)}\nFlyV: {len(flyv)}\n"
        f"FlyF: {len(flyf)}\nFlyT: {len(flyt)}\ntotal: {len(links)}"
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
