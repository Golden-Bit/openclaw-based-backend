"""Genera una coppia di chiavi Ed25519 in base64 (raw).

Uso:
  python scripts/gen_ed25519_keys.py

Output:
  - PRIVATE_KEY_B64
  - PUBLIC_KEY_B64

Questi valori possono essere usati in .env:
  OPENCLAW_WS_PRIVATE_KEY_B64=...
  OPENCLAW_WS_PUBLIC_KEY_B64=...
  OPENCLAW_WS_DEVICE_ID=<string>

Nota: la modalità device signing dipende dalla configurazione di OpenClaw.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def main() -> None:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    print("OPENCLAW_WS_PRIVATE_KEY_B64=", base64.b64encode(priv_raw).decode("ascii"))
    print("OPENCLAW_WS_PUBLIC_KEY_B64=", base64.b64encode(pub_raw).decode("ascii"))


if __name__ == "__main__":
    main()
