"""
Client WebSocket (RPC) verso OpenClaw Gateway.

OpenClaw usa frame JSON con tipi:
- req:  richiesta RPC (method + params)
- res:  risposta RPC (ok/payload o error)
- event: eventi server->client (es: connect.challenge, streaming eventi agent/tool)

Handshake richiesto (operator):
1) server -> event: connect.challenge { nonce, ts }
2) client -> req: connect { params ... }  (PRIMO frame "logico" del client, subito dopo challenge)
3) server -> res: payload hello-ok

Vincoli importanti (schema):
- minProtocol/maxProtocol devono matchare PROTOCOL_VERSION (attualmente 3) o il server rifiuta. :contentReference[oaicite:4]{index=4}
- Per il profilo operator "CLI-like", la doc mostra:
  client.id = "cli"
  client.mode = "operator"
  role = "operator"
  scopes = ["operator.read", "operator.write"]
  caps/commands/permissions presenti (anche vuoti)
  locale/userAgent presenti
  device presente e firmato :contentReference[oaicite:5]{index=5}

Device identity + firma:
- La doc richiede che TUTTE le connessioni firmino la challenge nonce e includano `device`. :contentReference[oaicite:6]{index=6}
- Questo client:
  * genera una identità Ed25519 persistente al primo avvio (state dir locale)
  * calcola device.id come fingerprint (sha256 del public key raw)
  * invia publicKey e signature base64url (senza padding)
  * firma un payload "v2" compatibile (legacy accettato) con nonce server :contentReference[oaicite:7]{index=7}

Compatibilità websockets:
- websockets >= 15/16 usa `additional_headers` (NON extra_headers)

Bug fix:
- niente deadlock: connect() non chiama call()
- timeout espliciti: nessuna "attesa infinita"
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.core.config import settings


# ---------------------------
# Models
# ---------------------------

@dataclass
class WSHello:
    """Rappresentazione minimale del payload hello-ok."""
    protocol: int
    features: dict
    policy: dict
    raw: dict


# ---------------------------
# Helpers: base64url (no padding)
# ---------------------------

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------
# Device identity persistence
# ---------------------------

def _default_state_dir() -> Path:
    # Stato persistente BFF (chiavi device + deviceToken). Non usare /tmp.
    # Puoi override con env OPENCLAW_BFF_STATE_DIR se vuoi.
    base = os.getenv("OPENCLAW_BFF_STATE_DIR")
    if base:
        return Path(base).expanduser().resolve()
    return Path.home() / ".openclaw-bff"


def _identity_path(state_dir: Path) -> Path:
    return state_dir / "device_identity.json"


def _device_token_path(state_dir: Path) -> Path:
    return state_dir / "device_token.json"


def _load_device_identity(state_dir: Path) -> dict:
    """
    Carica identità dal file state.
    Se assente, genera e salva.
    Formato:
      {
        "id": "<hex sha256(pub_raw)>",
        "publicKey": "<base64url(raw pub)>",
        "privateKeyB64": "<base64url(raw priv)>"
      }
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    p = _identity_path(state_dir)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))

    # genera nuova Ed25519
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # fingerprint: sha256(pub_raw) hex
    dev_id = hashlib.sha256(pub_raw).hexdigest()

    # raw private key bytes (32)
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    ident = {
        "id": dev_id,
        "publicKey": _b64url_encode(pub_raw),
        "privateKeyB64": _b64url_encode(priv_raw),
    }
    p.write_text(json.dumps(ident, indent=2), encoding="utf-8")
    return ident


def _load_device_token(state_dir: Path) -> Optional[str]:
    """
    Carica deviceToken (se presente) salvato dall'hello-ok precedente.
    Il deviceToken NON sostituisce gateway token, ma può entrare nel payload di firma
    come "token" firmato (pattern comune: se deviceToken esiste, firmi con quello).
    """
    p = _device_token_path(state_dir)
    if not p.exists():
        return None
    try:
        j = json.loads(p.read_text(encoding="utf-8"))
        return j.get("deviceToken")
    except Exception:
        return None


def _save_device_token(state_dir: Path, device_token: str, meta: dict) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    p = _device_token_path(state_dir)
    payload = {"deviceToken": device_token, "meta": meta, "savedAtMs": _now_ms()}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------
# Client
# ---------------------------

class OpenClawWSClient:
    def __init__(self, url: str):
        self.url = url

        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}

        self.hello: Optional[WSHello] = None
        self._lock = asyncio.Lock()

        # challenge ricevuta (durante handshake) se usiamo listener
        self._last_challenge: Optional[dict] = None

        # timeouts (evitano attese infinite)
        self._connect_timeout = float(os.getenv("OPENCLAW_WS_CONNECT_TIMEOUT", "10"))
        self._rpc_timeout = float(os.getenv("OPENCLAW_WS_RPC_TIMEOUT", "20"))

        # state dir (device identity + device token)
        self._state_dir = _default_state_dir()

    # ---------------------------
    # Handshake + connect
    # ---------------------------

    async def connect(self) -> WSHello:
        """
        Connette e completa l'handshake.

        Nota: OpenClaw richiede:
        - challenge -> firma nonce -> connect
        - client.id / client.mode coerenti con schema (es: cli/operator) :contentReference[oaicite:8]{index=8}
        - minProtocol/maxProtocol=3 :contentReference[oaicite:9]{index=9}
        - device identity presente e firmata :contentReference[oaicite:10]{index=10}
        """
        async with self._lock:
            if self._ws is not None and self.hello is not None:
                return self.hello

            # half-open cleanup
            if self._ws is not None and self.hello is None:
                await self.close()

            # header Authorization (gateway auth token)
            additional_headers: Optional[List[Tuple[str, str]]] = None
            if settings.openclaw_bearer_token:
                additional_headers = [("Authorization", f"Bearer {settings.openclaw_bearer_token}")]

            try:
                # 1) open socket
                self._ws = await websockets.connect(
                    self.url,
                    max_size=10 * 1024 * 1024,
                    additional_headers=additional_headers,
                    ping_interval=20,
                    ping_timeout=20,
                    open_timeout=self._connect_timeout,
                    close_timeout=10,
                )

                # 2) ricevi challenge (OBBLIGATORIA)
                challenge = await self._recv_challenge()

                nonce = str(challenge.get("nonce") or "")
                ts = int(challenge.get("ts") or _now_ms())

                if not nonce:
                    raise RuntimeError("connect.challenge missing nonce")

                # 3) device identity + firma
                ident = _load_device_identity(self._state_dir)
                device_token = _load_device_token(self._state_dir)

                device = self._sign_device_v2(
                    ident=ident,
                    nonce=nonce,
                    ts=ts,
                    # client e role DEVONO matchare schema/shape del connect
                    client_id="cli",
                    client_mode="operator",
                    role="operator",
                    scopes=["operator.read", "operator.write"],
                    # token da includere nella firma: se esiste deviceToken, preferiscilo
                    token=(device_token or settings.openclaw_bearer_token or ""),
                )

                # 4) params (match doc shape)
                # ATTENZIONE: valori costanti come da doc per operator CLI-like :contentReference[oaicite:11]{index=11}
                connect_params: Dict[str, Any] = {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "client": {
                        "id": "cli",
                        "version": "1.0.0",
                        "platform": self._platform_string(),
                        "mode": "operator",
                    },
                    "role": "operator",
                    "scopes": ["operator.read", "operator.write"],
                    # per schema: presenti anche vuoti :contentReference[oaicite:12]{index=12}
                    "caps": [],
                    "commands": [],
                    "permissions": {},
                    "auth": {"token": settings.openclaw_bearer_token or ""},
                    "locale": os.getenv("OPENCLAW_LOCALE", "en-US"),
                    "userAgent": os.getenv("OPENCLAW_USER_AGENT", "openclaw-bff/0.1.0"),
                    "device": device,
                }

                # 5) invia connect e attendi response
                hello_payload = await self._rpc_handshake("connect", connect_params, timeout=self._connect_timeout)

                if not isinstance(hello_payload, dict):
                    raise RuntimeError(f"Unexpected hello payload type: {type(hello_payload)}")

                # 6) salva eventuale deviceToken per reconnect futuri (hello-ok.auth.deviceToken) :contentReference[oaicite:13]{index=13}
                auth = hello_payload.get("auth") or {}
                if isinstance(auth, dict) and auth.get("deviceToken"):
                    _save_device_token(self._state_dir, auth["deviceToken"], meta={"role": auth.get("role"), "scopes": auth.get("scopes")})

                self.hello = WSHello(
                    protocol=int(hello_payload.get("protocol", 0)),
                    features=hello_payload.get("features", {}) or {},
                    policy=hello_payload.get("policy", {}) or {},
                    raw=hello_payload,
                )

                # 7) start listener AFTER handshake (evita race durante connect)
                self._listener_task = asyncio.create_task(self._listener())

                return self.hello

            except Exception:
                await self.close()
                raise

    async def _recv_challenge(self) -> dict:
        """
        Attende il frame connect.challenge.
        Il protocollo richiede che tutte le connessioni firmino la nonce. :contentReference[oaicite:14]{index=14}
        """
        assert self._ws is not None
        raw = await asyncio.wait_for(self._ws.recv(), timeout=self._connect_timeout)
        data = json.loads(raw)

        if data.get("type") != "event" or data.get("event") != "connect.challenge":
            raise RuntimeError(f"Expected connect.challenge event, got: {data.get('type')} {data.get('event')}")

        payload = data.get("payload") or {}
        if not isinstance(payload, dict):
            raise RuntimeError("connect.challenge payload is not an object")
        return payload

    def _platform_string(self) -> str:
        """
        Ritorna una stringa platform compatibile (best-effort).
        La doc usa esempi tipo 'macos', 'ios'. :contentReference[oaicite:15]{index=15}
        """
        p = os.sys.platform
        if p.startswith("linux"):
            return "linux"
        if p.startswith("darwin"):
            return "macos"
        if p.startswith("win"):
            return "windows"
        return "linux"

    def _sign_device_v2(
        self,
        ident: dict,
        nonce: str,
        ts: int,
        client_id: str,
        client_mode: str,
        role: str,
        scopes: List[str],
        token: str,
    ) -> dict:
        """
        Firma "v2" (legacy) con nonce server.

        Payload v2 (stringa deterministica):
          v2|deviceId|clientId|clientMode|role|scopes_csv|ts|token|nonce

        Nota: la doc consiglia v3 ma indica che v2 rimane accettato per compatibilità. :contentReference[oaicite:16]{index=16}
        """
        device_id = ident["id"]
        pub_b64url = ident["publicKey"]
        priv_raw = _b64url_decode(ident["privateKeyB64"])
        priv = Ed25519PrivateKey.from_private_bytes(priv_raw)

        scopes_csv = ",".join(scopes)

        payload = "|".join(
            [
                "v2",
                device_id,
                client_id,
                client_mode,
                role,
                scopes_csv,
                str(ts),
                token,
                nonce,
            ]
        ).encode("utf-8")

        sig = priv.sign(payload)
        sig_b64url = _b64url_encode(sig)

        return {
            "id": device_id,
            "publicKey": pub_b64url,
            "signature": sig_b64url,
            "signedAt": ts,
            "nonce": nonce,
        }

    async def _rpc_handshake(self, method: str, params: dict, timeout: float) -> Any:
        """
        RPC minimale usata SOLO durante handshake (prima che il listener parta).
        Invia req e aspetta un singolo res.
        """
        assert self._ws is not None
        req_id = uuid.uuid4().hex

        await self._ws.send(
            json.dumps({"type": "req", "id": req_id, "method": method, "params": params})
        )

        raw = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
        data = json.loads(raw)

        if data.get("type") != "res" or data.get("id") != req_id:
            raise RuntimeError(f"Unexpected handshake response frame: {data}")

        if data.get("ok") is not True:
            # error è tipicamente {code, message, details?...}
            err = data.get("error") or {}
            raise RuntimeError(str(err))

        return data.get("payload")

    # ---------------------------
    # RPC post-handshake
    # ---------------------------

    async def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> Any:
        """
        RPC high-level: garantisce connessione + hello poi invia la request.
        """
        if self._ws is None or self.hello is None:
            await self.connect()

        assert self._ws is not None

        req_id = uuid.uuid4().hex
        frame = {"type": "req", "id": req_id, "method": method, "params": params or {}}

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending[req_id] = fut

        await self._ws.send(json.dumps(frame))
        return await asyncio.wait_for(fut, timeout=timeout or self._rpc_timeout)

    async def _listener(self) -> None:
        """Loop principale: riceve frame e risolve pending futures / registra eventi."""
        assert self._ws is not None
        try:
            async for msg in self._ws:
                data = json.loads(msg)
                t = data.get("type")

                if t == "res":
                    req_id = data.get("id")
                    fut = self._pending.pop(req_id, None)
                    if fut and not fut.done():
                        if data.get("ok") is True:
                            fut.set_result(data.get("payload"))
                        else:
                            fut.set_exception(RuntimeError(str(data.get("error") or "WS RPC error")))

                elif t == "event":
                    # per ora memorizziamo solo la challenge (debug) + lasciamo estensioni future
                    if data.get("event") == "connect.challenge":
                        self._last_challenge = data.get("payload")

                else:
                    pass

        except Exception:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("WebSocket closed"))
            self._pending.clear()

    async def close(self) -> None:
        """Chiude WS e resetta lo stato interno (idempotente)."""
        if self._listener_task:
            self._listener_task.cancel()

        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass

        self._ws = None
        self.hello = None

        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(RuntimeError("WS client closed"))
        self._pending.clear()
        self._last_challenge = None