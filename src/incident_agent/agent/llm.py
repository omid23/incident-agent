"""Model adapters with tool calling: Anthropic Messages API and OpenAI-compatible chat.

The agent works on a provider-neutral transcript:

* ``{"role": "user", "content": str}``
* ``{"role": "assistant", "content": str, "tool_calls": [ToolCall, ...]}``
* ``{"role": "tool", "tool_call_id": str, "name": str, "content": str, "is_error": bool}``

Each adapter converts that to its wire format. Plain httpx, no SDKs, so the
request shapes are visible and testable.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    latency_ms: float = 0.0


class LLMError(Exception):
    pass


class LLM(Protocol):
    name: str
    model: str

    def complete(self, system: str, messages: list[dict], tools: Sequence[ToolSpec]) -> LLMResponse: ...


RETRY = {408, 409, 429, 500, 502, 503, 504, 529}


def _post_with_retry(client: httpx.Client, url: str, headers: dict, body: dict, retries: int) -> dict:
    last = ""
    for attempt in range(retries + 1):
        try:
            resp = client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if resp.status_code == 200:
                return resp.json()
            last = f"HTTP {resp.status_code}: {resp.text[:300]}"
            if resp.status_code not in RETRY:
                break
        if attempt < retries:
            time.sleep(min(2 ** attempt, 8))
    raise LLMError(last)


class AnthropicLLM:
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-5-5", *, max_tokens: int = 2048, api_key_env: str = "ANTHROPIC_API_KEY",
                 base_url: str = "https://api.anthropic.com", retries: int = 3, client: httpx.Client | None = None):
        self.model, self.max_tokens, self.api_key_env = model, max_tokens, api_key_env
        self.base_url, self.retries = base_url.rstrip("/"), retries
        self._client = client or httpx.Client(timeout=120)

    @staticmethod
    def to_wire(messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks: list[dict] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                if m.get("is_error"):
                    block["is_error"] = True
                # Consecutive tool results belong in one user turn.
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) \
                        and out[-1]["content"] and out[-1]["content"][0].get("type") == "tool_result":
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def complete(self, system: str, messages: list[dict], tools: Sequence[ToolSpec]) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": self.to_wire(messages),
        }
        if tools:
            body["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]
        headers = {"x-api-key": os.environ.get(self.api_key_env, ""), "anthropic-version": "2023-06-01",
                   "content-type": "application/json"}
        started = time.perf_counter()
        data = _post_with_retry(self._client, f"{self.base_url}/v1/messages", headers, body, self.retries)
        text, calls = [], []
        for block in data.get("content") or []:
            if block.get("type") == "text":
                text.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                calls.append(ToolCall(block["id"], block["name"], block.get("input") or {}))
        usage = data.get("usage") or {}
        return LLMResponse("".join(text), calls, data.get("stop_reason", ""), int(usage.get("input_tokens") or 0),
                           int(usage.get("output_tokens") or 0), data.get("model", self.model),
                           (time.perf_counter() - started) * 1000)


class OpenAICompatLLM:
    """OpenAI, Azure OpenAI (via base_url), vLLM, Ollama and other compatible servers."""

    name = "openai"

    def __init__(self, model: str = "gpt-6-luna", *, base_url: str = "https://api.openai.com/v1",
                 api_key_env: str = "OPENAI_API_KEY", max_tokens: int = 2048, retries: int = 3,
                 client: httpx.Client | None = None):
        self.model, self.base_url, self.api_key_env = model, base_url.rstrip("/"), api_key_env
        self.max_tokens, self.retries = max_tokens, retries
        self._client = client or httpx.Client(timeout=120)

    @staticmethod
    def to_wire(system: str, messages: list[dict]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                msg: dict[str, Any] = {"role": "assistant", "content": m.get("content") or None}
                if m.get("tool_calls"):
                    msg["tool_calls"] = [{"id": tc.id, "type": "function",
                                          "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                                         for tc in m["tool_calls"]]
                out.append(msg)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        return out

    def complete(self, system: str, messages: list[dict], tools: Sequence[ToolSpec]) -> LLMResponse:
        body: dict[str, Any] = {"model": self.model, "messages": self.to_wire(system, messages),
                                "max_completion_tokens": self.max_tokens}
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                                "parameters": t.parameters}} for t in tools]
        headers = {"Authorization": f"Bearer {os.environ.get(self.api_key_env, '')}"}
        started = time.perf_counter()
        data = _post_with_retry(self._client, f"{self.base_url}/chat/completions", headers, body, self.retries)
        try:
            choice = data["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError) as exc:
            raise LLMError("response has no choices") from exc
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_raw": fn.get("arguments")}
            calls.append(ToolCall(tc.get("id", ""), fn.get("name", ""), args if isinstance(args, dict) else {}))
        usage = data.get("usage") or {}
        return LLMResponse(msg.get("content") or "", calls, choice.get("finish_reason", ""),
                           int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
                           data.get("model", self.model), (time.perf_counter() - started) * 1000)


class ScriptedLLM:
    """Deterministic stand-in for tests and demos: replays responses or calls a policy function."""

    name = "scripted"
    model = "scripted"

    def __init__(self, script: Sequence[LLMResponse] | Callable[[str, list[dict]], LLMResponse]):
        self._script = script
        self._i = 0
        self.calls: list[list[dict]] = []

    def complete(self, system: str, messages: list[dict], tools: Sequence[ToolSpec]) -> LLMResponse:
        self.calls.append(list(messages))
        if callable(self._script):
            return self._script(system, messages)
        if self._i >= len(self._script):
            raise LLMError("script exhausted")
        resp = self._script[self._i]
        self._i += 1
        return resp


def make_llm(provider: str, model: str | None = None, **kwargs) -> LLM:
    if provider == "anthropic":
        return AnthropicLLM(model or "claude-sonnet-5-5", **kwargs)
    if provider == "openai":
        return OpenAICompatLLM(model or "gpt-6-luna", **kwargs)
    raise ValueError(f"unknown provider '{provider}' (anthropic | openai)")
