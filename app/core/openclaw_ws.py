"""
Client WebSocket (RPC) verso OpenClaw Gateway.

Frame JSON:
- req:   {"type":"req","id":"...", "method":"...", "params":{...}}
- res:   {"type":"res","id":"...", "ok":true, "payload":{...}} oppure ok:false,error
- event: {"type":"event","event":"...", "payload":{...}}

Handshake (schema strict, basato su quello che la tua build richiede):
1) server -> event: connect.challenge { nonce, ts? }
2) client -> req: connect { minProtocol/maxProtocol/client/role/scopes/... + device(signature) }
3) server -> res: hello-ok payload

Identity/device:
- Il tuo OPENCLAW CLI salva identity in ~/.openclaw/identity/device.json con PEM:
    publicKeyPem / privateKeyPem / deviceId
- Questo client RIUSA quella identity (OPENCLAW_IDENTITY_FILE) e firma la challenge.
  Questo è necessario per evitare "device signature invalid".

WS debug (NUOVO):
- OPENCLAW_WS_DEBUG=1 abilita log di:
  - ogni evento WS: eventName + stream + runId + keys(payload)
  - ogni res errore
- subscribe_all(): permette di ricevere TUTTI gli eventi WS (qualunque event name),
  così puoi capire se i tool events arrivano su event diverso da "agent".

Nota websockets:
- websockets >= 15/16 usa additional_headers (NON extra_headers).
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
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from app.core.config import settings


# =============================================================================
# Models
# =============================================================================

@dataclass
class WSHello:
    protocol: int
    features: dict
    policy: dict
    raw: dict


@dataclass
class WSEvent:
    event: str
    payload: dict


# =============================================================================
# Helpers: base64url (no padding) + decode tolerant
# =============================================================================

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _b64_any_decode(s: str) -> bytes:
    s = (s or "").strip().strip('"').strip("'")
    if not s:
        return b""
    try:
        if "-" in s or "_" in s:
            return _b64url_decode(s)
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.b64decode((s + pad).encode("utf-8"))
    except Exception:
        try:
            return _b64url_decode(s)
        except Exception:
            return b""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if (v is not None and v != "") else default


def _ws_debug_enabled() -> bool:
    return (_env("OPENCLAW_WS_DEBUG", "0") or "0").lower() in ("1", "true", "yes", "on")


def _dbg(*args: Any) -> None:
    if _ws_debug_enabled():
        # stampa semplice su stdout; uvicorn lo mostra in console
        print("[openclaw_ws DEBUG]", *args)


def _get_gateway_token() -> str:
    return (
        _env("OPENCLAW_BEARER_TOKEN")
        or _env("OPENCLAW_GATEWAY_TOKEN")
        or getattr(settings, "openclaw_bearer_token", "")
        or ""
    )


def _get_client_id() -> str:
    return _env("OPENCLAW_CLIENT_ID", "gateway-client") or "gateway-client"


def _get_client_mode() -> str:
    return _env("OPENCLAW_CLIENT_MODE", "backend") or "backend"


def _get_role() -> str:
    return _env("OPENCLAW_ROLE", "operator") or "operator"


def _get_scopes() -> List[str]:
    raw = _env("OPENCLAW_SCOPES", "operator.read,operator.write") or ""
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts or ["operator.read", "operator.write"]


def _platform_string() -> str:
    p = os.sys.platform
    if p.startswith("linux"):
        return "linux"
    if p.startswith("darwin"):
        return "macos"
    if p.startswith("win"):
        return "windows"
    return "linux"


# =============================================================================
# Device identity loading (CLI PEM)
# =============================================================================

def _state_dir() -> Path:
    base = _env("OPENCLAW_STATE_DIR") or _env("OPENCLAW_BFF_STATE_DIR")
    if base:
        return Path(base).expanduser().resolve()
    return (Path.home() / ".openclaw-bff").resolve()


def _identity_path(sd: Path) -> Path:
    return sd / "device_identity.json"


def _read_json(path: Path) -> Optional[dict]:
    try:
        j = json.loads(path.read_text(encoding="utf-8"))
        return j if isinstance(j, dict) else None
    except Exception:
        return None


def _load_identity_from_cli_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    return _read_json(path)


def _pem_to_ed25519_private_raw(pem_str: str) -> bytes:
    pem = pem_str.replace("\\n", "\n").strip().encode("utf-8")
    key = load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError(f"Identity privateKeyPem is not Ed25519 (got {type(key)})")
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    if len(raw) != 32:
        raise RuntimeError(f"Invalid Ed25519 raw private length from PEM: {len(raw)} (expected 32)")
    return raw


def _pem_to_ed25519_public_raw(pem_str: str) -> bytes:
    pem = pem_str.replace("\\n", "\n").strip().encode("utf-8")
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError(f"Identity publicKeyPem is not Ed25519 (got {type(key)})")
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    if len(raw) != 32:
        raise RuntimeError(f"Invalid Ed25519 raw public length from PEM: {len(raw)} (expected 32)")
    return raw


def _generate_identity(sd: Path) -> dict:
    """
    Fallback identity locale (sconsigliata nel tuo setup, ma tenuta come fallback).
    """
    sd.mkdir(parents=True, exist_ok=True)
    p = _identity_path(sd)
    if p.exists():
        j = _read_json(p)
        if j:
            return j

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    dev_id = hashlib.sha256(pub_raw).hexdigest()

    ident = {
        "id": dev_id,
        "publicKey": _b64url_encode(pub_raw),
        "privateKeyB64": _b64url_encode(priv_raw),
    }
    p.write_text(json.dumps(ident, indent=2), encoding="utf-8")
    return ident


def _normalize_identity(raw: dict) -> tuple[str, bytes, bytes]:
    """
    Normalizza identity a:
      (device_id_str, pub_raw(32), priv_raw(32))

    Supporta:
    - PEM: publicKeyPem/privateKeyPem (tuo caso)
    - base64: publicKey/privateKeyB64...
    """
    dev_id = (
        raw.get("deviceId")
        or raw.get("id")
        or raw.get("device_id")
        or raw.get("deviceID")
        or ""
    )
    dev_id = str(dev_id)

    pub_raw = b""
    priv_raw = b""

    if isinstance(raw.get("privateKeyPem"), str) and raw["privateKeyPem"].strip():
        priv_raw = _pem_to_ed25519_private_raw(raw["privateKeyPem"])
    if isinstance(raw.get("publicKeyPem"), str) and raw["publicKeyPem"].strip():
        pub_raw = _pem_to_ed25519_public_raw(raw["publicKeyPem"])

    if not priv_raw:
        priv_s = (
            raw.get("privateKeyB64")
            or raw.get("privateKey")
            or raw.get("secretKey")
            or raw.get("ed25519PrivateKey")
            or raw.get("private_key")
            or ""
        )
        if priv_s:
            priv_raw = _b64_any_decode(str(priv_s))

    if not pub_raw:
        pub_s = (
            raw.get("publicKey")
            or raw.get("publicKeyB64")
            or raw.get("publicKeyBase64")
            or raw.get("public_key")
            or ""
        )
        if pub_s:
            pub_raw = _b64_any_decode(str(pub_s))

    if len(priv_raw) == 64:
        priv_raw = priv_raw[:32]
    if len(priv_raw) != 32:
        raise RuntimeError(f"Invalid Ed25519 private key length: {len(priv_raw)} (expected 32)")

    priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
    if not pub_raw:
        pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if len(pub_raw) != 32:
        raise RuntimeError(f"Invalid Ed25519 public key length: {len(pub_raw)} (expected 32)")

    if not dev_id:
        dev_id = hashlib.sha256(pub_raw).hexdigest()

    return dev_id, pub_raw, priv_raw


# =============================================================================
# Client
# =============================================================================

class OpenClawWSClient:
    def __init__(self, url: str):
        self.url = url

        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}

        self.hello: Optional[WSHello] = None
        self._lock = asyncio.Lock()

        # subscriptions
        # (event_name, run_id_filter, queue)
        self._subs: List[Tuple[Optional[str], Optional[str], asyncio.Queue]] = []

        # timeouts
        self._connect_timeout = float(_env("OPENCLAW_WS_CONNECT_TIMEOUT", "10") or "10")
        self._rpc_timeout = float(_env("OPENCLAW_WS_RPC_TIMEOUT", "20") or "20")

        # identity source
        self._identity_file = _env("OPENCLAW_IDENTITY_FILE") or str(Path.home() / ".openclaw" / "identity" / "device.json")
        self._state_dir = _state_dir()

        # cached identity
        self._device_id: Optional[str] = None
        self._pub_raw: Optional[bytes] = None
        self._priv_raw: Optional[bytes] = None

    # -------------------------------------------------------------------------
    # Identity
    # -------------------------------------------------------------------------

    def _load_identity(self) -> None:
        if self._device_id and self._pub_raw and self._priv_raw:
            return

        raw_ident: Optional[dict] = None

        if self._identity_file:
            p = Path(self._identity_file).expanduser().resolve()
            raw_ident = _load_identity_from_cli_file(p)
            _dbg("identity file:", str(p), "loaded:", bool(raw_ident))

        if raw_ident is None:
            raw_ident = _generate_identity(self._state_dir)
            _dbg("identity fallback generated in:", str(self._state_dir))

        dev_id, pub_raw, priv_raw = _normalize_identity(raw_ident)
        self._device_id = dev_id
        self._pub_raw = pub_raw
        self._priv_raw = priv_raw

        _dbg("identity normalized:", {"deviceId": self._device_id, "pubLen": len(pub_raw), "privLen": len(priv_raw)})

    def _build_device_signature(
        self,
        *,
        nonce: str,
        ts_ms: int,
        token: str,
        client_id: str,
        client_mode: str,
        role: str,
        scopes: List[str],
    ) -> dict:
        """
        Firma v2:
          v2|deviceId|clientId|clientMode|role|scopes_csv|ts|token|nonce
        """
        self._load_identity()
        assert self._device_id and self._pub_raw and self._priv_raw

        scopes_csv = ",".join(scopes)
        payload = "|".join(
            ["v2", self._device_id, client_id, client_mode, role, scopes_csv, str(ts_ms), token or "", nonce]
        ).encode("utf-8")

        priv = Ed25519PrivateKey.from_private_bytes(self._priv_raw)
        sig = priv.sign(payload)

        return {
            "id": self._device_id,
            "publicKey": _b64url_encode(self._pub_raw),
            "signature": _b64url_encode(sig),
            "signedAt": ts_ms,
            "nonce": nonce,
        }

    # -------------------------------------------------------------------------
    # Handshake / connect
    # -------------------------------------------------------------------------

    async def connect(self) -> WSHello:
        async with self._lock:
            if self._ws is not None and self.hello is not None:
                return self.hello

            if self._ws is not None and self.hello is None:
                await self.close()

            token = _get_gateway_token()
            additional_headers: Optional[List[Tuple[str, str]]] = None
            if token:
                additional_headers = [("Authorization", f"Bearer {token}")]

            try:
                self._ws = await websockets.connect(
                    self.url,
                    additional_headers=additional_headers,
                    max_size=10 * 1024 * 1024,
                    ping_interval=20,
                    ping_timeout=20,
                    open_timeout=self._connect_timeout,
                    close_timeout=10,
                )

                challenge = await self._recv_challenge()
                nonce = str(challenge.get("nonce") or "")
                ts = int(challenge.get("ts") or _now_ms())
                if not nonce:
                    raise RuntimeError("connect.challenge missing nonce")

                client_id = _get_client_id()
                client_mode = _get_client_mode()
                role = _get_role()
                scopes = _get_scopes()

                device = self._build_device_signature(
                    nonce=nonce,
                    ts_ms=ts,
                    token=token,
                    client_id=client_id,
                    client_mode=client_mode,
                    role=role,
                    scopes=scopes,
                )

                connect_params: Dict[str, Any] = {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "client": {"id": client_id, "mode": client_mode, "platform": _platform_string(), "version": "0.1.0"},
                    "role": role,
                    "scopes": scopes,
                    "caps": [],
                    "commands": [],
                    "permissions": {},
                    "locale": _env("OPENCLAW_LOCALE", "en-US"),
                    "userAgent": _env("OPENCLAW_USER_AGENT", "openclaw-bff/0.1.0"),
                    "auth": {"token": token} if token else {},
                    "device": device,
                }

                hello_payload = await self._rpc_handshake("connect", connect_params, timeout=self._connect_timeout)
                if not isinstance(hello_payload, dict):
                    raise RuntimeError(f"Unexpected hello payload type: {type(hello_payload)}")

                self.hello = WSHello(
                    protocol=int(hello_payload.get("protocol", 0)),
                    features=hello_payload.get("features", {}) or {},
                    policy=hello_payload.get("policy", {}) or {},
                    raw=hello_payload,
                )

                self._listener_task = asyncio.create_task(self._listener())
                _dbg("WS connected. hello.protocol=", self.hello.protocol)

                return self.hello

            except Exception as e:
                _dbg("WS connect failed:", repr(e))
                await self.close()
                raise

    async def _recv_challenge(self) -> dict:
        assert self._ws is not None
        raw = await asyncio.wait_for(self._ws.recv(), timeout=self._connect_timeout)
        data = json.loads(raw)

        if data.get("type") != "event" or data.get("event") != "connect.challenge":
            raise RuntimeError(f"Expected connect.challenge event, got: {data.get('type')} {data.get('event')}")

        payload = data.get("payload") or {}
        if not isinstance(payload, dict):
            raise RuntimeError("connect.challenge payload is not an object")
        return payload

    async def _rpc_handshake(self, method: str, params: dict, timeout: float) -> Any:
        assert self._ws is not None
        req_id = uuid.uuid4().hex
        await self._ws.send(json.dumps({"type": "req", "id": req_id, "method": method, "params": params}))

        raw = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
        data = json.loads(raw)

        if data.get("type") != "res" or data.get("id") != req_id:
            raise RuntimeError(f"Unexpected handshake response frame: {data}")

        if data.get("ok") is not True:
            _dbg("handshake res error:", data.get("error"))
            raise RuntimeError(str(data.get("error") or {}))

        return data.get("payload")

    # -------------------------------------------------------------------------
    # RPC post-handshake
    # -------------------------------------------------------------------------

    async def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> Any:
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

    # -------------------------------------------------------------------------
    # Subscriptions (event stream)
    # -------------------------------------------------------------------------

    async def subscribe(self, event_name: str, run_id: Optional[str] = None) -> AsyncGenerator[WSEvent, None]:
        """
        Sottoscrive SOLO un event name (es: "agent") con filtro runId opzionale.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs.append((event_name, run_id, q))
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            self._subs = [s for s in self._subs if s[2] is not q]

    async def subscribe_all(self, run_id: Optional[str] = None) -> AsyncGenerator[WSEvent, None]:
        """
        Sottoscrive TUTTI gli event name (debug). Utile per capire dove arrivano i tool events.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._subs.append((None, run_id, q))
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            self._subs = [s for s in self._subs if s[2] is not q]

    async def _listener(self) -> None:
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
                            err = data.get("error")
                            _dbg("RPC error res:", {"id": req_id, "error": err})
                            fut.set_exception(RuntimeError(str(err or "WS RPC error")))

                elif t == "event":
                    ev = str(data.get("event") or "")
                    payload_any = data.get("payload")
                    payload = payload_any if isinstance(payload_any, dict) else {"raw": payload_any}

                    run_id = str(payload.get("runId") or payload.get("run_id") or "")
                    stream = payload.get("stream") if isinstance(payload, dict) else None

                    if _ws_debug_enabled():
                        keys = list(payload.keys()) if isinstance(payload, dict) else []
                        _dbg("EVENT:", {"event": ev, "stream": stream, "runId": run_id, "keys": keys})

                    ws_event = WSEvent(event=ev, payload=payload if isinstance(payload, dict) else {"raw": payload})

                    # broadcast
                    for wanted_ev, wanted_run, q in list(self._subs):
                        if wanted_ev is not None and wanted_ev != ev:
                            continue
                        if wanted_run and wanted_run != run_id:
                            continue
                        try:
                            q.put_nowait(ws_event)
                        except asyncio.QueueFull:
                            # consumer lento: droppa
                            pass

                else:
                    pass

        except Exception as e:
            _dbg("listener stopped:", repr(e))
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("WebSocket closed"))
            self._pending.clear()

    # -------------------------------------------------------------------------
    # Close
    # -------------------------------------------------------------------------

    async def close(self) -> None:
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
        self._subs.clear()