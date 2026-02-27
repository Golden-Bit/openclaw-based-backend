"""Client WebSocket (RPC) verso OpenClaw Gateway.

Questo modulo implementa un client *robusto* per il protocollo WS di OpenClaw.

Perché serve:
- il Gateway WS è l'unico canale che espone la *Agent Loop pipeline completa*.
- tramite WS possiamo ricevere eventi separati per stream: assistant/text, tool, lifecycle, ecc.

Frame types (Gateway Protocol):
- req  (client -> server) : {type:'req', id, method, params}
- res  (server -> client) : {type:'res', id, ok, payload|error}
- event(server -> client) : {type:'event', event, payload, ...}

Handshake richiesto:
1) gateway -> event connect.challenge { nonce, ts }
2) client  -> req connect { params ... }
3) gateway -> res hello-ok (protocol/policy/features + eventuale auth.deviceToken)

Compatibilità websockets:
- websockets >= 15/16 usa `additional_headers` (non `extra_headers`).

Device identity:
- Il Gateway richiede una device identity firmata. Qui generiamo una Ed25519 al primo avvio
  e la persistiamo su disco (state dir).
- La firma usa un payload deterministico v2. Se la tua build richiede un payload diverso,
  modifica `_sign_device_v2()`.

Event bus:
- puoi iscriverti a `subscribe(event_name, run_id)` e ricevere frame `event` filtrati
  opzionalmente per runId (utile per `event: agent` dell'agent loop).
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import settings


@dataclass
class WSHello:
    """Rappresentazione minimale del payload hello-ok."""

    protocol: int
    features: dict
    policy: dict
    raw: dict


@dataclass
class WSEvent:
    """Evento gateway generico (frame type='event')."""

    event: str
    payload: dict
    frame: dict


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _now_ms() -> int:
    return int(time.time() * 1000)


def _parse_scopes(raw: str) -> List[str]:
    """Parsa una lista scopes da stringa comma-separated (es: "a,b,c")."""

    return [p.strip() for p in (raw or "").split(",") if p.strip()]


def _default_state_dir() -> Path:
    # Stato persistente (chiavi device + deviceToken).
    # Compat: alcuni setup usano OPENCLAW_STATE_DIR, altri OPENCLAW_BFF_STATE_DIR.
    base = os.getenv("OPENCLAW_STATE_DIR") or os.getenv("OPENCLAW_BFF_STATE_DIR")
    if base:
        return Path(base).expanduser().resolve()
    return Path.home() / ".openclaw-bff"


def _identity_path(state_dir: Path) -> Path:
    return state_dir / "device_identity.json"


def _device_token_path(state_dir: Path) -> Path:
    return state_dir / "device_token.json"


def _load_device_identity(state_dir: Path) -> dict:
    """Carica identità dal file state; se assente, genera e salva."""

    # Se l'utente ha già una device identity del CLI, può riutilizzarla:
    # OPENCLAW_IDENTITY_FILE=~/.openclaw/identity/device.json
    override = os.getenv("OPENCLAW_IDENTITY_FILE")
    if override:
        op = Path(override).expanduser()
        if op.exists():
            try:
                j = json.loads(op.read_text(encoding="utf-8"))
                # Ci aspettiamo i campi (o equivalenti) usati da questo BFF.
                # Se la shape è diversa, ignoriamo e usiamo l'identità del BFF.
                if all(k in j for k in ("id", "publicKey", "privateKeyB64")):
                    return j
            except Exception:
                pass

    state_dir.mkdir(parents=True, exist_ok=True)
    p = _identity_path(state_dir)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    dev_id = hashlib.sha256(pub_raw).hexdigest()

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
    payload = {"deviceToken": device_token, "meta": meta, "savedAtMs": _now_ms()}
    _device_token_path(state_dir).write_text(json.dumps(payload, indent=2), encoding="utf-8")


class OpenClawWSClient:
    """WS RPC client verso OpenClaw Gateway."""

    def __init__(self, url: str):
        self.url = url

        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._listener_task: Optional[asyncio.Task] = None

        # Pending requests: req_id -> Future(payload)
        self._pending: Dict[str, asyncio.Future] = {}

        self.hello: Optional[WSHello] = None
        self._lock = asyncio.Lock()

        # Timeouts (evitano attese infinite)
        self._connect_timeout = float(os.getenv("OPENCLAW_WS_CONNECT_TIMEOUT", "10"))
        self._rpc_timeout = float(os.getenv("OPENCLAW_WS_RPC_TIMEOUT", "20"))

        # Stato persistente (device identity + device token)
        self._state_dir = _default_state_dir()

        # Event subscriptions: list[(event_name, run_id, queue)]
        self._subs_lock = asyncio.Lock()
        self._subs: List[Tuple[str, Optional[str], asyncio.Queue]] = []

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def connect(self) -> WSHello:
        """Connette e completa l'handshake."""

        async with self._lock:
            if self._ws is not None and self.hello is not None:
                return self.hello

            # Half-open cleanup
            if self._ws is not None and self.hello is None:
                await self.close()

            # ------------------------------------------------------------------
            # Auth + client identity (DA ENV)
            #
            # La tua installazione OpenClaw valida rigidamente `client.mode` (e spesso anche `client.id`)
            # contro un set di costanti nel JSON schema. Quindi non possiamo hardcodare valori "operator".
            #
            # Usiamo questi env (che tu hai già nel tuo .env funzionante):
            # - OPENCLAW_CLIENT_ID
            # - OPENCLAW_CLIENT_MODE
            # - OPENCLAW_ROLE
            # - OPENCLAW_SCOPES (comma-separated)
            #
            # Nota token:
            # - in Settings abbiamo OPENCLAW_GATEWAY_TOKEN -> settings.openclaw_bearer_token
            # - ma alcuni .env usano OPENCLAW_BEARER_TOKEN. Supportiamo entrambe.
            # ------------------------------------------------------------------

            bearer = settings.openclaw_bearer_token or os.getenv("OPENCLAW_BEARER_TOKEN") or ""
            client_id = os.getenv("OPENCLAW_CLIENT_ID", "cli")
            client_mode = os.getenv("OPENCLAW_CLIENT_MODE", "backend")
            role = os.getenv("OPENCLAW_ROLE", "operator")
            scopes = _parse_scopes(os.getenv("OPENCLAW_SCOPES", "operator.read,operator.write"))

            additional_headers: Optional[List[Tuple[str, str]]] = None
            if bearer:
                additional_headers = [("Authorization", f"Bearer {bearer}")]

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

                # 2) receive challenge
                challenge = await self._recv_challenge()
                nonce = str(challenge.get("nonce") or "")
                ts = int(challenge.get("ts") or _now_ms())
                if not nonce:
                    raise RuntimeError("connect.challenge missing nonce")

                # 3) device identity + signature
                ident = _load_device_identity(self._state_dir)
                device_token = _load_device_token(self._state_dir)
                device = self._sign_device_v2(
                    ident=ident,
                    nonce=nonce,
                    ts=ts,
                    client_id=client_id,
                    client_mode=client_mode,
                    role=role,
                    scopes=scopes,
                    token=(device_token or bearer),
                )

                # 4) connect params (schema-strict)
                connect_params: Dict[str, Any] = {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "client": {
                        "id": client_id,
                        "version": os.getenv("OPENCLAW_CLIENT_VERSION", "openclaw-bff/0.1.0"),
                        "platform": self._platform_string(),
                        "mode": client_mode,
                    },
                    "role": role,
                    "scopes": scopes,
                    "caps": [],
                    "commands": [],
                    "permissions": {},
                    "auth": {"token": bearer},
                    "locale": os.getenv("OPENCLAW_LOCALE", "en-US"),
                    "userAgent": os.getenv("OPENCLAW_USER_AGENT", "openclaw-bff/0.1.0"),
                    "device": device,
                }

                # 5) handshake RPC (single response)
                hello_payload = await self._rpc_handshake("connect", connect_params, timeout=self._connect_timeout)
                if not isinstance(hello_payload, dict):
                    raise RuntimeError(f"Unexpected hello payload type: {type(hello_payload)}")

                # Save deviceToken if provided
                auth = hello_payload.get("auth") or {}
                if isinstance(auth, dict) and auth.get("deviceToken"):
                    _save_device_token(
                        self._state_dir,
                        auth["deviceToken"],
                        meta={"role": auth.get("role"), "scopes": auth.get("scopes")},
                    )

                self.hello = WSHello(
                    protocol=int(hello_payload.get("protocol", 0)),
                    features=hello_payload.get("features", {}) or {},
                    policy=hello_payload.get("policy", {}) or {},
                    raw=hello_payload,
                )

                # 6) start listener post-handshake
                self._listener_task = asyncio.create_task(self._listener())
                return self.hello

            except Exception:
                await self.close()
                raise

    async def _recv_challenge(self) -> dict:
        assert self._ws is not None
        raw = await asyncio.wait_for(self._ws.recv(), timeout=self._connect_timeout)
        data = json.loads(raw)
        if data.get("type") != "event" or data.get("event") != "connect.challenge":
            raise RuntimeError(
                f"Expected connect.challenge event, got: {data.get('type')} {data.get('event')}"
            )
        payload = data.get("payload") or {}
        if not isinstance(payload, dict):
            raise RuntimeError("connect.challenge payload is not an object")
        return payload

    def _platform_string(self) -> str:
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
        """Firma v2 (legacy) con nonce server.

        Payload v2 (stringa deterministica):
          v2|deviceId|clientId|clientMode|role|scopes_csv|ts|token|nonce
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
        """RPC minimale usata SOLO durante handshake (prima del listener)."""

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
            raise RuntimeError(str(data.get("error") or {}))
        return data.get("payload")

    # ------------------------------------------------------------------
    # RPC post-handshake
    # ------------------------------------------------------------------

    async def call(self, method: str, params: Optional[dict] = None, timeout: Optional[float] = None) -> Any:
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

    # ------------------------------------------------------------------
    # Event subscriptions
    # ------------------------------------------------------------------

    async def subscribe(self, event_name: str, run_id: Optional[str] = None) -> AsyncGenerator[WSEvent, None]:
        """Sottoscrive eventi gateway (frame event) filtrando opzionalmente per runId."""

        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        async with self._subs_lock:
            self._subs.append((event_name, run_id, q))

        try:
            while True:
                ev = await q.get()
                if isinstance(ev, WSEvent) and ev.event == "__closed__":
                    return
                yield ev
        finally:
            async with self._subs_lock:
                self._subs = [s for s in self._subs if s[2] is not q]

    async def _fanout_event(self, event_name: str, payload: dict, frame: dict) -> None:
        ev = WSEvent(event=event_name, payload=payload, frame=frame)
        run_id = payload.get("runId") if isinstance(payload, dict) else None

        async with self._subs_lock:
            subs = list(self._subs)

        for sub_event, sub_run, q in subs:
            if sub_event != event_name:
                continue
            if sub_run is not None and run_id is not None and sub_run != run_id:
                continue
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                # se il consumer è lento, droppiamo (meglio che bloccare la listener)
                pass

    # ------------------------------------------------------------------
    # Listener
    # ------------------------------------------------------------------

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
                            fut.set_exception(RuntimeError(str(data.get("error") or "WS RPC error")))

                elif t == "event":
                    event_name = data.get("event") or ""
                    payload = data.get("payload") or {}
                    if isinstance(payload, dict):
                        await self._fanout_event(event_name, payload, data)

        except Exception:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("WebSocket closed"))
            self._pending.clear()

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

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

        # chiudi anche tutte le subscription
        async with self._subs_lock:
            subs = list(self._subs)
            self._subs.clear()
        for _, _, q in subs:
            try:
                q.put_nowait(WSEvent(event="__closed__", payload={}, frame={}))
            except Exception:
                pass
