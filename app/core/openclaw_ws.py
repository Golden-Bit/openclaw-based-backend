"""Client WebSocket (RPC) verso OpenClaw Gateway.

OpenClaw usa frame JSON con tipi:
- req/res/event

Handshake tipico:
1) server -> event: connect.challenge
2) client -> req: connect { ... }
3) server -> res/hello-ok

⚠️ Nota: alcune installazioni richiedono una device identity firmata (Ed25519).
Questo client supporta:
- auth token (Authorization nel connect.auth)
- opzionale device signing se OPENCLAW_WS_DEVICE_ID + OPENCLAW_WS_PRIVATE_KEY_B64 sono configurati.

Se la tua installazione ha regole diverse, modifica i campi `device` nel payload.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.core.config import settings


@dataclass
class WSHello:
    protocol: int
    features: dict
    policy: dict
    raw: dict


class OpenClawWSClient:
    def __init__(self, url: str):
        self.url = url
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._pending: Dict[str, asyncio.Future] = {}
        self._listener_task: Optional[asyncio.Task] = None
        self.hello: Optional[WSHello] = None
        self._lock = asyncio.Lock()
        self._last_challenge: Optional[dict] = None

        # Optional device signing
        self.device_id = None
        self._priv = None
        self._pub_b64 = None

        # Read optional envs if present
        # (non sono nel Settings per non forzare configurazione)
        import os

        dev_id = os.getenv("OPENCLAW_WS_DEVICE_ID")
        priv_b64 = os.getenv("OPENCLAW_WS_PRIVATE_KEY_B64")
        pub_b64 = os.getenv("OPENCLAW_WS_PUBLIC_KEY_B64")

        if dev_id and priv_b64:
            self.device_id = dev_id
            raw_priv = base64.b64decode(priv_b64)
            self._priv = Ed25519PrivateKey.from_private_bytes(raw_priv)
            if pub_b64:
                self._pub_b64 = pub_b64
            else:
                pub = self._priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                self._pub_b64 = base64.b64encode(pub).decode("ascii")

    async def connect(self) -> WSHello:
        async with self._lock:
            if self._ws is not None:
                return self.hello  # type: ignore[return-value]

            self._ws = await websockets.connect(self.url, max_size=10 * 1024 * 1024)

            # Start listener ASAP
            self._listener_task = asyncio.create_task(self._listener())

            # Wait for challenge event (or fallback timeout)
            challenge = await self._wait_for_challenge(timeout=5)

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

            # If challenge arrives and we have a device key, attach device signature.
            if challenge and self._priv and self.device_id and self._pub_b64:
                nonce = str(challenge.get("nonce") or "")
                signed_at = int(time.time() * 1000)

                # Heuristic signing payload: many implementations sign a deterministic string
                # that includes version marker + deviceId + nonce + timestamp.
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

            # Call connect method
            res = await self.call("connect", connect_params)

            # Some servers return hello-ok as payload in res
            hello_payload = res
            self.hello = WSHello(
                protocol=int(hello_payload.get("protocol", 0)),
                features=hello_payload.get("features", {}),
                policy=hello_payload.get("policy", {}),
                raw=hello_payload,
            )
            return self.hello

    async def _wait_for_challenge(self, timeout: float = 5.0) -> Optional[dict]:
        """Attende un connect.challenge (event)."""
        start = time.time()
        while time.time() - start < timeout:
            if getattr(self, "_last_challenge", None) is not None:
                ch = self._last_challenge
                self._last_challenge = None
                return ch
            await asyncio.sleep(0.05)
        return None

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
                            fut.set_exception(RuntimeError(data.get("error") or "WS RPC error"))
                elif t == "event":
                    # Store challenge event for handshake
                    if data.get("event") == "connect.challenge":
                        self._last_challenge = data.get("payload")
                    # Other events can be handled in higher-level streaming bridges.
                else:
                    # ignore unknown
                    pass
        except Exception:
            # Fail pending futures
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("WebSocket closed"))
            self._pending.clear()

    async def call(self, method: str, params: dict | None = None, timeout: float = 20.0) -> Any:
        """Esegue una chiamata RPC e ritorna payload."""
        if self._ws is None:
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
        if self._listener_task:
            self._listener_task.cancel()
        if self._ws:
            await self._ws.close()
        self._ws = None
        self.hello = None
