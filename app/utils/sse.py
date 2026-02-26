"""Utility per gestire Server-Sent Events (SSE).

OpenResponses e ChatCompletions in OpenClaw possono streammare via SSE.
Questo modulo permette di:
- parsare un flusso bytes in eventi SSE
- serializzare eventi SSE verso il client

Formato SSE (semplificato):

  event: <name>\n
  data: <json>\n
  \n
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import AsyncGenerator, Optional


@dataclass
class SSEEvent:
    event: str
    data: str

    def json(self) -> dict:
        return json.loads(self.data)


async def iter_sse_events(byte_stream: AsyncGenerator[bytes, None]) -> AsyncGenerator[SSEEvent, None]:
    """Converte un AsyncGenerator di bytes in SSEEvent."""

    buffer = ""
    async for chunk in byte_stream:
        buffer += chunk.decode("utf-8", errors="ignore")
        while "\n\n" in buffer:
            raw, buffer = buffer.split("\n\n", 1)
            event_name: Optional[str] = None
            data_lines = []
            for line in raw.splitlines():
                if line.startswith("event:"):
                    event_name = line[len("event:") :].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[len("data:") :].strip())

            if event_name is None:
                # Alcuni stream usano solo data
                event_name = "message"
            data = "\n".join(data_lines) if data_lines else ""
            yield SSEEvent(event=event_name, data=data)


def format_sse(event: str, data: str) -> bytes:
    """Serializza un evento SSE."""
    return f"event: {event}\n" f"data: {data}\n\n".encode("utf-8")
