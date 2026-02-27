"""
Client WebSocket (RPC) verso OpenClaw Gateway.

OpenClaw usa frame JSON con tipi:
- req:  richiesta RPC (method + params)
- res:  risposta RPC (ok/payload o error)
- event: eventi server->client (es: connect.challenge, chat stream, ecc.)

Handshake tipico (semplificato):
1) (opzionale) server -> event: connect.challenge
2) client -> req: connect { ... }
3) server -> res: payload hello-ok (protocol/policy/features)

⚠️ Nota "device identity":
Alcune installazioni richiedono una device identity firmata (Ed25519) in `connect_params.device`.
Questo client supporta device signing se sono presenti env vars:
- OPENCLAW_WS_DEVICE_ID
- OPENCLAW_WS_PRIVATE_KEY_B64 (ed25519 raw 32 bytes in base64)
- OPENCLAW_WS_PUBLIC_KEY_B64 (opzionale; se assente viene derivata dalla private)

Auth token:
- supportato in due modi:
  A) Header del WS handshake: Authorization: Bearer <token>
  B) Campo connect_params.auth.token

Compatibilità websockets:
- websockets >= 15/16 usa `additional_headers` (NON `extra_headers`)

Fix critico:
- NESSUN DEADLOCK: connect() non chiama call().
  In precedenza: connect() -> call("connect") -> call() richiamava connect() perché hello==None.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.core.config import settings


@dataclass
class WSHello:
    """Rappresentazione minimale del payload hello-ok."""
    protocol: int
    features: dict
    policy: dict
    raw: dict


class OpenClawWSClient:
    def __init__(self, url: str):
        self.url = url

        # WebSocket instance + listener
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._listener_task: Optional[asyncio.Task] = None

        # Pending requests: req_id -> Future(payload)
        self._pending: Dict[str, asyncio.Future] = {}

        # Hello-ok (popolato dopo connect)
        self.hello: Optional[WSHello] = None

        # Serialize connect() calls
        self._lock = asyncio.Lock()

        # Last connect.challenge payload (if any)
        self._last_challenge: Optional[dict] = None

        # Optional device signing config (read directly from env)
        self.device_id: Optional[str] = None
        self._priv: Optional[Ed25519PrivateKey] = None
        self._pub_b64: Optional[str] = None

        # Timeouts (evitano "attese infinite")
        self._connect_timeout = 10.0
        self._rpc_timeout = 20.0

        import os
        dev_id = os.getenv("OPENCLAW_WS_DEVICE_ID")
        priv_b64 = os.getenv("OPENCLAW_WS_PRIVATE_KEY_B64")
        pub_b64 = os.getenv("OPENCLAW_WS_PUBLIC_KEY_B64")

        if dev_id and priv_b64:
            self.device_id = dev_id
            raw_priv = base64.b64decode(priv_b64)
            self._priv = Ed25519PrivateKey.from_private_bytes(raw_priv)

            # Public key: if not provided, derive it
            if pub_b64:
                self._pub_b64 = pub_b64
            else:
                pub = self._priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                self._pub_b64 = base64.b64encode(pub).decode("ascii")

    async def connect(self) -> WSHello:
        """
        Connette e fa handshake RPC "connect".

        - Se già connesso con hello valido: ritorna subito.
        - Se ws esiste ma hello è None: reset (half-open) -> close() e riprova.
        - Se handshake fallisce: close() e rilancia eccezione.

        Ritorna sempre WSHello se OK, altrimenti alza eccezione.
        """
        async with self._lock:
            # Already connected
            if self._ws is not None and self.hello is not None:
                return self.hello

            # Half-open: ws exists but hello is missing => reset
            if self._ws is not None and self.hello is None:
                await self.close()

            # Prepare auth header (websockets 16 uses additional_headers)
            additional_headers: Optional[List[Tuple[str, str]]] = None
            if settings.openclaw_bearer_token:
                additional_headers = [("Authorization", f"Bearer {settings.openclaw_bearer_token}")]

            try:
                # 1) Open WS
                self._ws = await websockets.connect(
                    self.url,
                    max_size=10 * 1024 * 1024,
                    additional_headers=additional_headers,
                    ping_interval=20,
                    ping_timeout=20,
                    open_timeout=self._connect_timeout,
                    close_timeout=10,
                )

                # 2) Start listener ASAP
                self._listener_task = asyncio.create_task(self._listener())

                # 3) Best-effort wait for challenge (short)
                challenge = await self._wait_for_challenge(timeout=0.5)

                # 4) Build connect params
                connect_params: Dict[str, Any] = {
                    "minProtocol": 1,
                    "maxProtocol": 3,
                    "client": {
                        "id": "openclaw-bff",
                        "version": "0.1.0",
                        "platform": "server",
                        "mode": "bff",
                        "displayName": "OpenClaw BFF",
                    },
                    "role": "operator",
                    "scopes": ["operator.read", "operator.write"],
                    "auth": {},
                }

                if settings.openclaw_bearer_token:
                    connect_params["auth"]["token"] = settings.openclaw_bearer_token

                # Optional device signature
                if challenge and self._priv and self.device_id and self._pub_b64:
                    nonce = str(challenge.get("nonce") or "")
                    signed_at = int(time.time() * 1000)
                    payload = f"v1|{self.device_id}|{signed_at}|{nonce}".encode("utf-8")
                    sig = self._priv.sign(payload)
                    sig_b64 = base64.b64encode(sig).decode("ascii")

                    connect_params["device"] = {
                        "id": self.device_id,
                        "publicKey": self._pub_b64,
                        "signature": sig_b64,
                        "signedAt": signed_at,
                        "nonce": nonce,
                    }

                # 5) IMPORTANT: send connect as raw req (NO call(), otherwise deadlock)
                hello_payload = await self._rpc_raw("connect", connect_params, timeout=self._connect_timeout)

                if not isinstance(hello_payload, dict):
                    raise RuntimeError(f"Unexpected hello payload type: {type(hello_payload)}")

                self.hello = WSHello(
                    protocol=int(hello_payload.get("protocol", 0)),
                    features=hello_payload.get("features", {}) or {},
                    policy=hello_payload.get("policy", {}) or {},
                    raw=hello_payload,
                )
                return self.hello

            except Exception:
                # If anything fails, reset state so the next connect() is clean.
                await self.close()
                raise

    async def _rpc_raw(self, method: str, params: dict | None, timeout: float) -> Any:
        """
        RPC low-level: invia un req e aspetta il res corrispondente.

        Non richiama connect() e non richiede hello già presente.
        Serve proprio per implementare l'handshake connect senza deadlock.
        """
        if self._ws is None:
            raise RuntimeError("WS is not open")

        req_id = uuid.uuid4().hex
        frame = {"type": "req", "id": req_id, "method": method, "params": params or {}}

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending[req_id] = fut

        await self._ws.send(json.dumps(frame))
        return await asyncio.wait_for(fut, timeout=timeout)

    async def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> Any:
        """
        RPC high-level: garantisce connessione + hello poi invia la request.

        Nota: non usare per method='connect'. L'handshake lo gestisce connect().
        """
        if method == "connect":
            raise RuntimeError("Do not call method 'connect' via call(); use connect().")

        if self._ws is None or self.hello is None:
            await self.connect()

        assert self._ws is not None

        return await self._rpc_raw(method, params, timeout=timeout or self._rpc_timeout)

    async def _wait_for_challenge(self, timeout: float = 0.5) -> Optional[dict]:
        """Attende un event connect.challenge per un tempo breve (best-effort)."""
        start = time.time()
        while time.time() - start < timeout:
            if self._last_challenge is not None:
                ch = self._last_challenge
                self._last_challenge = None
                return ch
            await asyncio.sleep(0.05)
        return None

    async def _listener(self) -> None:
        """Riceve frame dal WS e risolve Future pendenti / memorizza challenge."""
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
                            fut.set_exception(RuntimeError(data.get("error") or "WS RPC error"))

                elif t == "event":
                    if data.get("event") == "connect.challenge":
                        self._last_challenge = data.get("payload")

                else:
                    # ignore unknown
                    pass

        except Exception:
            # Fail pending futures if WS closes unexpectedly
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

        # Fail any pending futures explicitly (avoid hanging awaits)
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(RuntimeError("WS client closed"))
        self._pending.clear()

        self._last_challenge = None