"""Helper per OpenResponses.

OpenClaw espone un endpoint compatibile `/v1/responses`.
La struttura risposta è simile al formato OpenAI Responses.

Questo modulo fornisce:
- estrazione testo finale (best-effort)
"""

from __future__ import annotations

from typing import Any, Dict, List


def extract_output_text(resp: Dict[str, Any]) -> str:
    """Estrae il testo dell'assistente dalla risposta OpenResponses.

    Implementazione "best-effort" per gestire varianti.
    """

    # OpenAI Responses style: output = [{type:'message', content:[{type:'output_text', text:'...'}]}]
    out = resp.get("output")
    if isinstance(out, list):
        chunks: List[str] = []
        for item in out:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for c in content:
                    if isinstance(c, dict) and c.get("type") in {"output_text", "text"}:
                        t = c.get("text") or c.get("value")
                        if isinstance(t, str):
                            chunks.append(t)
        if chunks:
            return "".join(chunks)

    # Alternative: output_text field
    if isinstance(resp.get("output_text"), str):
        return resp["output_text"]

    # Fallback: try choices
    choices = resp.get("choices")
    if isinstance(choices, list) and choices:
        ch0 = choices[0]
        if isinstance(ch0, dict):
            msg = ch0.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]

    return ""
