from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - handled at runtime
    OpenAI = None  # type: ignore[assignment]


@dataclass(slots=True)
class OpenAIConfig:
    model: str = "gpt-5"
    temperature: float = 1


class OpenAIModelClient:
    def __init__(self, config: OpenAIConfig) -> None:
        self.config = config
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required")
        if OpenAI is None:
            raise RuntimeError("openai package is not installed")
        self._client = OpenAI(api_key=api_key)

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        completion = self._client.chat.completions.create(
            model=self.config.model,
            temperature=self.config.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = completion.choices[0].message.content or "{}"
        return _loads_json(content)

    def chat_text(self, system_prompt: str, user_prompt: str) -> str:
        completion = self._client.chat.completions.create(
            model=self.config.model,
            temperature=self.config.temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return completion.choices[0].message.content or ""


def _loads_json(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    return json.loads(raw)
