from __future__ import annotations

import logging
from typing import Any

import httpx

from cyber_risk.config.settings import Settings

logger = logging.getLogger(__name__)

GROQ_CHAT_COMPLETIONS_URL = "https://api.groq.com/openai/v1/chat/completions"


def groq_api_key(settings: Settings) -> str | None:
    """Prefer dedicated Groq key; fall back to OPENAI_API_KEY (common convention)."""
    return (settings.groq_api_key or settings.openai_api_key or "").strip() or None


def groq_model_name(settings: Settings) -> str:
    return (settings.groq_model or settings.openai_model or "llama-3.1-8b-instant").strip()


def _chat_completion(
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    timeout: float = 120.0,
) -> str:
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    with httpx.Client(timeout=timeout) as client:
        r = client.post(
            GROQ_CHAT_COMPLETIONS_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
    r.raise_for_status()
    data = r.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("Groq returned no choices")
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("Groq returned empty content")
    return content.strip()


def polish_briefing_markdown(markdown: str, settings: Settings) -> str:
    """
    Improve readability and tone only. Facts (CVEs, asset IDs, scores) must remain unchanged.
    """
    key = groq_api_key(settings)
    if not key:
        raise ValueError("Groq API key missing (set GROQ_API_KEY or OPENAI_API_KEY)")

    model = groq_model_name(settings)
    system = (
        "You are an editor for cybersecurity executive briefings. "
        "Rewrite the user's Markdown for clarity, brevity, and professional tone. "
        "CRITICAL: Do not add, remove, or change any factual data — CVE IDs, CVSS numbers, "
        "asset names/IDs, composite scores, control IDs (e.g. SI-2), dates, or quoted NIST excerpts. "
        "Keep heading structure (##, ###) and code fences. Output Markdown only, no preamble."
    )
    user = f"Edit this briefing:\n\n{markdown}"
    return _chat_completion(key, model, [{"role": "system", "content": system}, {"role": "user", "content": user}])


def should_use_groq(settings: Settings) -> bool:
    return settings.llm_provider.strip().lower() == "groq" and groq_api_key(settings) is not None
