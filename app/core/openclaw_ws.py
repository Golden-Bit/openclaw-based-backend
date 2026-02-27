"""
Client WebSocket (RPC) verso OpenClaw Gateway.

OpenClaw usa frame JSON con tipi:
- req:  richiesta RPC (method + params)
- res:  risposta RPC (ok/payload o error)
- event: eventi server->client (es: connect.challenge, chat stream, ecc.)

Handshake tipico (semplificato):
1) server -> event: connect.challenge (opzionale, dipende dalla build/config)
2) client -> req: connect { ... }  (DEVE arrivare presto dopo l'apertura WS)
3) server -> res: hello-ok payload (policy + features.methods/events + snapshot)

⚠️ Nota "device identity":
Alcune installazioni richiedono una device identity firmata (Ed25519) in `connect_params.device`.
Questo client supporta device signing se sono presenti env vars:
- OPENCLAW_WS_DEVICE_ID
- OPENCLAW_WS_PRIVATE_KEY_B64 (ed25519 raw 32 bytes in base64)
- OPENCLAW_WS_PUBLIC_KEY_B64 (opzionale; se assente viene derivata dalla private)

Auth token:
- Questo client supporta token Bearer in due modi:
  A) Header HTTP del WebSocket handshake: Authorization: Bearer <token>
  B) Campo connect_params.auth.token (alcune build lo usano)

Compatibilità websockets:
- Con websockets >= 15/16 l'argomento per gli header si chiama `additional_headers`
  (NON `extra_headers`).
  Signature (16.0): websockets.connect(..., additional_headers=..., ...)

Bug fixes rispetto alla versione base:
- connect() non ritorna mai None: o WSHello o eccezione
- se la prima handshake fallisce, pulisce _ws e hello (evita stato half-open)
- non aspetta 5s per la challenge prima di inviare connect: best-effort (0.5s)
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

            # Prepare auth header (best compatibility)
            additional_headers: Optional[List[Tuple[str, str]]] = None
            if settings.openclaw_bearer_token:
                additional_headers = [("Authorization", f"Bearer {settings.openclaw_bearer_token}")]

            try:
                # IMPORTANT: websockets 16.x uses `additional_headers` (not extra_headers)
                self._ws = await websockets.connect(
                    self.url,
                    max_size=10 * 1024 * 1024,
                    additional_headers=additional_headers,
                    ping_interval=20,
                    ping_timeout=20,
                    open_timeout=10,
                    close_timeout=10,
                )

                # Start listener ASAP (so we can receive events/responses)
                self._listener_task = asyncio.create_task(self._listener())

                # Best-effort challenge wait (short). Some builds won't send it at all.
                challenge = await self._wait_for_challenge(timeout=0.5)

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

                # Token also inside connect payload (some builds use it here)
                if settings.openclaw_bearer_token:
                    connect_params["auth"]["token"] = settings.openclaw_bearer_token

                # Optional device signature (only if we have keys and a challenge/nonce)
                if challenge and self._priv and self.device_id and self._pub_b64:
                    nonce = str(challenge.get("nonce") or "")
                    signed_at = int(time.time() * 1000)

                    # NOTE: payload format can vary by build; this is a common deterministic format.
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

                # Perform connect RPC
                hello_payload = await self.call("connect", connect_params)

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
                    # challenge used during handshake
                    if data.get("event") == "connect.challenge":
                        self._last_challenge = data.get("payload")

                else:
                    # ignore unknown frame
                    pass

        except Exception:
            # If WS closes unexpectedly: fail all pending futures
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("WebSocket closed"))
            self._pending.clear()

    async def call(self, method: str, params: dict | None = None, timeout: float = 20.0) -> Any:
        """
        Esegue una chiamata RPC e ritorna payload.

        NOTE:
        - call() assicura che connect() sia stato completato (hello non-None).
        - se il WS cade, solleva eccezione.
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
        return await asyncio.wait_for(fut, timeout=timeout)

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
        self._pending.clear()
        self._last_challenge = None