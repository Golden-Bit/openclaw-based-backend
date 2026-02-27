"""
Client WebSocket (RPC) verso OpenClaw Gateway.

Frame JSON:
- req:  richiesta RPC (method + params)
- res:  risposta (ok/payload | ok=false/error)
- event: eventi server -> client (es: connect.challenge, streaming, broadcast)

Handshake (server side):
- Il PRIMO request del client deve essere method="connect" e params devono validare lo schema.
  In caso contrario: INVALID_REQUEST e close(1008).  (vedi message-handler.ts)
- Il server può inviare prima un event connect.challenge con { nonce, ts }.
- minProtocol/maxProtocol devono includere PROTOCOL_VERSION (attualmente 3).

Client schema (importante per questo bug):
- client.id deve essere uno dei GATEWAY_CLIENT_IDS (es: "gateway-client", "cli", ...)
- client.mode deve essere uno dei GATEWAY_CLIENT_MODES:
  webchat | cli | ui | backend | node | probe | test
  (NON "operator", NON "bff").

Device auth:
- Se vuoi che il gateway ti conceda scopes reali (operator.read/write), di solito serve una device identity,
  perché il gateway “default-deny” e può azzerare scopes se non riesce a legarli a un device/token.
- Il payload firmato deve essere EXACT match di buildDeviceAuthPayload() lato OpenClaw:
  v1|deviceId|clientId|clientMode|role|scopesCsv|signedAtMs|token
  v2 aggiunge |nonce se presente.

Questo file:
- non va mai in deadlock (connect() NON chiama call("connect"))
- non lascia stato half-open (_ws valorizzato ma hello None)
- usa timeouts espliciti (niente attese infinite)
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
from typing import Any, Dict, List, Optional, Tuple

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.core.config import settings

# Protocol version nel gateway (OpenClaw)
PROTOCOL_VERSION = 3


# ---------------------------
# Models
# ---------------------------

@dataclass
class WSHello:
    protocol: int
    features: dict
    policy: dict
    raw: dict


# ---------------------------
# base64url helpers (NO padding) - come infra/device-identity.ts
# ---------------------------

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------
# Device identity (compatibile col formato OpenClaw device.json)
# ---------------------------

def _expand_path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p))).resolve()


def _default_state_dir() -> Path:
    # Se l'utente ha già OpenClaw, preferiamo riusare ~/.openclaw (se esiste)
    home = Path.home()
    candidate = home / ".openclaw"
    if candidate.exists():
        return candidate
    return home / ".openclaw-bff"


def _resolve_identity_file() -> Path:
    # Priorità:
    # 1) OPENCLAW_IDENTITY_FILE (se impostato)
    # 2) OPENCLAW_STATE_DIR/identity/device.json (se OPENCLAW_STATE_DIR impostato)
    # 3) default_state_dir()/identity/device.json
    if getattr(settings, "openclaw_identity_file", None):
        return _expand_path(settings.openclaw_identity_file)  # type: ignore[attr-defined]

    if getattr(settings, "openclaw_state_dir", None):
        sd = _expand_path(settings.openclaw_state_dir)  # type: ignore[attr-defined]
        return sd / "identity" / "device.json"

    return _default_state_dir() / "identity" / "device.json"


def _ensure_parent(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def _derive_device_id_from_pub_raw(pub_raw_32: bytes) -> str:
    # OpenClaw usa sha256(pub_raw) hex
    return hashlib.sha256(pub_raw_32).hexdigest()


def _load_or_create_identity(identity_file: Path) -> tuple[str, str, Ed25519PrivateKey]:
    """
    Ritorna:
      (device_id_hex, public_key_raw_b64url, private_key_obj)

    Formato file compatibile con OpenClaw (infra/device-identity.ts):
      {
        "version": 1,
        "deviceId": "<sha256(pubRaw) hex>",
        "publicKeyPem": "-----BEGIN PUBLIC KEY----- ...",
        "privateKeyPem": "-----BEGIN PRIVATE KEY----- ...",
        "createdAtMs": 123
      }
    """
    _ensure_parent(identity_file)

    if identity_file.exists():
        data = json.loads(identity_file.read_text(encoding="utf-8"))
        pub_pem = data.get("publicKeyPem")
        priv_pem = data.get("privateKeyPem")
        if isinstance(pub_pem, str) and isinstance(priv_pem, str):
            priv = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
            if not isinstance(priv, Ed25519PrivateKey):
                raise RuntimeError("Device private key is not Ed25519")

            pub = priv.public_key()
            pub_raw = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            dev_id = _derive_device_id_from_pub_raw(pub_raw)
            pub_b64url = _b64url_encode(pub_raw)

            # Se deviceId nel file è diverso (file vecchio/corrotto), lo correggiamo
            if data.get("deviceId") != dev_id:
                data["deviceId"] = dev_id
                identity_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                try:
                    os.chmod(identity_file, 0o600)
                except Exception:
                    pass

            return dev_id, pub_b64url, priv  # type: ignore[return-value]

    # Genera nuova identità (Ed25519)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    dev_id = _derive_device_id_from_pub_raw(pub_raw)
    pub_b64url = _b64url_encode(pub_raw)

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    payload = {
        "version": 1,
        "deviceId": dev_id,
        "publicKeyPem": pub_pem,
        "privateKeyPem": priv_pem,
        "createdAtMs": _now_ms(),
    }
    identity_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(identity_file, 0o600)
    except Exception:
        pass

    return dev_id, pub_b64url, priv


def _device_token_file(identity_file: Path) -> Path:
    # accanto a identity/device.json → identity/device-auth.json (nome simile a OpenClaw)
    return identity_file.parent / "device-auth.json"


def _load_device_token(identity_file: Path) -> Optional[str]:
    p = _device_token_file(identity_file)
    if not p.exists():
        return None
    try:
        j = json.loads(p.read_text(encoding="utf-8"))
        # formato “nostro”: { "deviceToken": "...", "savedAtMs": ... }
        tok = j.get("deviceToken")
        return tok if isinstance(tok, str) and tok else None
    except Exception:
        return None


def _save_device_token(identity_file: Path, device_token: str) -> None:
    p = _device_token_file(identity_file)
    _ensure_parent(p)
    payload = {"deviceToken": device_token, "savedAtMs": _now_ms()}
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


# ---------------------------
# Device auth payload (EXACT match OpenClaw buildDeviceAuthPayload)
# ---------------------------

def _build_device_auth_payload(
    *,
    device_id: str,
    client_id: str,
    client_mode: str,
    role: str,
    scopes: List[str],
    signed_at_ms: int,
    token: str,
    nonce: Optional[str],
) -> str:
    """
    OpenClaw buildDeviceAuthPayload():
      version = (nonce ? "v2" : "v1")
      scopesCsv = scopes.join(",")
      base = [version, deviceId, clientId, clientMode, role, scopesCsv, signedAtMs, token]
      if v2: base.push(nonce)
      return base.join("|")
    """
    version = "v2" if nonce else "v1"
    scopes_csv = ",".join(scopes)
    parts = [
        version,
        device_id,
        client_id,
        client_mode,
        role,
        scopes_csv,
        str(signed_at_ms),
        token or "",
    ]
    if version == "v2":
        parts.append(nonce or "")
    return "|".join(parts)


# ---------------------------
# Client
# ---------------------------

class OpenClawWSClient:
    def __init__(self, url: str):
        self.url = url

        self._ws: Optional[Any] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}

        self.hello: Optional[WSHello] = None
        self._lock = asyncio.Lock()

        # timeouts
        self._connect_timeout = float(getattr(settings, "openclaw_ws_connect_timeout", 10.0))
        self._rpc_timeout = float(getattr(settings, "openclaw_ws_rpc_timeout", 20.0))
        self._challenge_timeout = float(getattr(settings, "openclaw_ws_challenge_timeout", 2.0))

        # identity paths
        self._identity_file = _resolve_identity_file()

    # ---------------------------
    # Connection + handshake
    # ---------------------------

    async def connect(self) -> WSHello:
        """
        Connette e completa handshake (connect).

        NOTE:
        - Non chiama call("connect") → niente deadlock.
        - Se fallisce → close() e rilancia eccezione.
        """
        async with self._lock:
            if self._ws is not None and self.hello is not None:
                return self.hello

            # half-open cleanup
            if self._ws is not None and self.hello is None:
                await self.close()

            # WS handshake headers (websockets 16 usa additional_headers)
            additional_headers: Optional[List[Tuple[str, str]]] = None
            if settings.openclaw_bearer_token:
                additional_headers = [("Authorization", f"Bearer {settings.openclaw_bearer_token}")]

            try:
                self._ws = await websockets.connect(
                    self.url,
                    additional_headers=additional_headers,
                    max_size=10 * 1024 * 1024,
                    open_timeout=self._connect_timeout,
                    close_timeout=10,
                    ping_interval=20,
                    ping_timeout=20,
                )

                # 1) Best-effort: leggi challenge (se arriva). Non bloccare troppo.
                nonce, ts = await self._recv_challenge_best_effort()

                # 2) Costruisci connect params validi per schema (client.mode deve essere ENUM!)
                connect_params = self._build_connect_params(nonce=nonce, ts=ts)

                # 3) Invia connect come PRIMO req del client e attendi res
                hello_payload = await self._handshake_connect(connect_params, timeout=self._connect_timeout)

                if not isinstance(hello_payload, dict):
                    raise RuntimeError(f"Unexpected hello payload type: {type(hello_payload)}")

                # salva deviceToken se presente (utile per reconnect futuri)
                auth = hello_payload.get("auth")
                if isinstance(auth, dict):
                    dt = auth.get("deviceToken")
                    if isinstance(dt, str) and dt:
                        _save_device_token(self._identity_file, dt)

                self.hello = WSHello(
                    protocol=int(hello_payload.get("protocol", 0)),
                    features=hello_payload.get("features", {}) or {},
                    policy=hello_payload.get("policy", {}) or {},
                    raw=hello_payload,
                )

                # 4) Start listener post-handshake
                self._listener_task = asyncio.create_task(self._listener())

                return self.hello

            except Exception:
                await self.close()
                raise

    async def _recv_challenge_best_effort(self) -> tuple[Optional[str], Optional[int]]:
        """
        Prova a ricevere connect.challenge.
        - Se arriva: ritorna (nonce, ts)
        - Se non arriva entro _challenge_timeout: ritorna (None, None) e si procede (payload v1)
        """
        assert self._ws is not None
        try:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=self._challenge_timeout)
        except asyncio.TimeoutError:
            return None, None

        try:
            data = json.loads(raw)
        except Exception:
            return None, None

        if data.get("type") == "event" and data.get("event") == "connect.challenge":
            payload = data.get("payload") or {}
            if isinstance(payload, dict):
                nonce = payload.get("nonce")
                ts = payload.get("ts")
                return (str(nonce) if nonce else None, int(ts) if isinstance(ts, (int, float)) else None)

        # Se non è challenge, lo ignoriamo (nel caso reale, challenge è quasi sempre il primo frame server->client)
        return None, None

    def _build_connect_params(self, nonce: Optional[str], ts: Optional[int]) -> Dict[str, Any]:
        """
        Costruisce ConnectParams (schema-valid) + device signature compatibile.

        Client defaults (BFF):
        - client.id   = gateway-client
        - client.mode = backend
        Valori ammessi: webchat|cli|ui|backend|node|probe|test
        """
        client_id = getattr(settings, "openclaw_client_id", "gateway-client")
        client_mode = getattr(settings, "openclaw_client_mode", "backend")
        role = getattr(settings, "openclaw_role", "operator")

        # scopes env: "a,b,c"
        scopes_str = getattr(settings, "openclaw_scopes", "operator.read,operator.write")
        scopes = [s.strip() for s in scopes_str.split(",") if s.strip()]

        signed_at = ts if isinstance(ts, int) and ts > 0 else _now_ms()

        # Preferisci deviceToken salvato (se abilitato), altrimenti gateway token
        use_device_token = bool(getattr(settings, "openclaw_use_device_token", True))
        saved_device_token = _load_device_token(self._identity_file) if use_device_token else None
        auth_token = saved_device_token or (settings.openclaw_bearer_token or "")

        # Device identity + signature (consigliata per mantenere scopes; v2 se nonce presente)
        device_id, pub_b64url, priv = _load_or_create_identity(self._identity_file)

        payload = _build_device_auth_payload(
            device_id=device_id,
            client_id=client_id,
            client_mode=client_mode,
            role=role,
            scopes=scopes,
            signed_at_ms=signed_at,
            token=auth_token,
            nonce=nonce,
        )
        sig = priv.sign(payload.encode("utf-8"))
        sig_b64url = _b64url_encode(sig)

        device = {
            "id": device_id,
            "publicKey": pub_b64url,        # base64url(raw pub) - no padding
            "signature": sig_b64url,        # base64url(sig) - no padding
            "signedAt": signed_at,          # ms
        }
        if nonce:
            device["nonce"] = nonce

        # ConnectParams (schema)
        return {
            "minProtocol": PROTOCOL_VERSION,
            "maxProtocol": PROTOCOL_VERSION,
            "client": {
                "id": client_id,
                "mode": client_mode,
                "version": os.getenv("BFF_VERSION", "0.1.0"),
                "platform": os.getenv("BFF_PLATFORM", "linux"),
                "displayName": os.getenv("BFF_DISPLAY_NAME", "OpenClaw BFF"),
            },
            "role": role,  # server accetta operator|node
            "scopes": scopes,
            # campi “presenti anche se vuoti” (tollerati dallo schema)
            "caps": [],
            "commands": [],
            "permissions": {},
            "locale": os.getenv("OPENCLAW_LOCALE", "en-US"),
            "userAgent": os.getenv("OPENCLAW_USER_AGENT", "openclaw-bff/0.1.0"),
            "auth": {
                # per handshake: token condiviso o deviceToken (se presente)
                "token": auth_token,
            },
            "device": device,
        }

    async def _handshake_connect(self, params: Dict[str, Any], timeout: float) -> Any:
        """
        Invia req connect e aspetta res connect (ok/payload).
        Durante handshake NON usiamo il listener/pending map (più semplice, meno race).
        """
        assert self._ws is not None
        req_id = uuid.uuid4().hex

        await self._ws.send(json.dumps({"type": "req", "id": req_id, "method": "connect", "params": params}))

        deadline = time.time() + timeout
        while time.time() < deadline:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=max(0.1, deadline - time.time()))
            data = json.loads(raw)

            # possono arrivare event vari; cerchiamo la res col nostro id
            if data.get("type") == "res" and data.get("id") == req_id:
                if data.get("ok") is True:
                    return data.get("payload")
                err = data.get("error") or {}
                raise RuntimeError(str(err))

        raise TimeoutError("WS handshake timed out waiting for connect response")

    # ---------------------------
    # RPC post-handshake
    # ---------------------------

    async def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> Any:
        """
        RPC standard dopo handshake.
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
        """
        Listener loop: gestisce res (risolve future) + memorizza event utili.
        """
        assert self._ws is not None
        try:
            async for msg in self._ws:
                data = json.loads(msg)
                if data.get("type") == "res":
                    req_id = data.get("id")
                    fut = self._pending.pop(req_id, None)
                    if fut and not fut.done():
                        if data.get("ok") is True:
                            fut.set_result(data.get("payload"))
                        else:
                            fut.set_exception(RuntimeError(str(data.get("error") or "WS RPC error")))
                else:
                    # eventi: per ora ignoriamo (aggiungeremo streaming più avanti)
                    pass
        except Exception:
            # fallisci pending futures
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("WebSocket closed"))
            self._pending.clear()

    async def close(self) -> None:
        """
        Chiude WS e resetta stato (idempotente).
        """
        if self._listener_task:
            self._listener_task.cancel()
            self._listener_task = None

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