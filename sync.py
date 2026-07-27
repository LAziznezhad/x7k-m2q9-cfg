#!/usr/bin/env python3
"""Remote config sync (v3 init + TOTP + ChaCha20-Poly1305)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
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
ROOT = Path(__file__).resolve().parent
OUT = ROOT / "hiddify_export" / "cfg.txt"


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


def rename_links(links: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for link in links:
        base = link.split("#", 1)[0].rstrip()
        if not base or base in seen:
            continue
        seen.add(base)
        unique.append(base)
    return [set_link_name(link, f"FlyB-{i}") for i, link in enumerate(unique, start=1)]


def http_get_json(url: str, extra: dict[str, str] | None = None) -> dict:
    headers = dict(HEADERS)
    if extra:
        headers.update(extra)
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=25, context=ctx) as resp:
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


def main() -> int:
    key = fetch_key()
    payload = fetch_payload(key)
    inner = payload["data"]
    text = decrypt(key, inner["secure"], inner["x1"], inner["x2"])
    links = rename_links(extract_links(text))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    print(f"ok count={len(links)} path={OUT}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
