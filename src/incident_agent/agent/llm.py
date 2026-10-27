"""Model adapters with tool calling: Anthropic Messages API, OpenAI-compatible chat, Google Cloud Vertex AI.

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
import shutil
import subprocess
import time
import uuid
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
        return self.parse(data, self.model, started)

    @staticmethod
    def parse(data: dict, model: str, started: float) -> LLMResponse:
        text, calls = [], []
        for block in data.get("content") or []:
            if block.get("type") == "text":
                text.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                calls.append(ToolCall(block["id"], block["name"], block.get("input") or {}))
        usage = data.get("usage") or {}
        return LLMResponse("".join(text), calls, data.get("stop_reason", ""), int(usage.get("input_tokens") or 0),
                           int(usage.get("output_tokens") or 0), data.get("model", model),
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


def gcloud_access_token() -> str:
    """An OAuth access token for Vertex AI: GOOGLE_OAUTH_ACCESS_TOKEN, or Application Default Credentials via gcloud."""
    token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "").strip()
    if token:
        return token
    gcloud = shutil.which("gcloud")
    if not gcloud:
        raise LLMError("no Google Cloud credentials: set GOOGLE_OAUTH_ACCESS_TOKEN, or install gcloud and run "
                       "`gcloud auth application-default login`")
    try:
        out = subprocess.run([gcloud, "auth", "application-default", "print-access-token"], capture_output=True,
                             text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LLMError(f"gcloud failed: {exc}") from exc
    if out.returncode != 0 or not out.stdout.strip():
        raise LLMError(f"gcloud could not print an access token: {out.stderr.strip()[:300]}")
    return out.stdout.strip()


class VertexLLM:
    """Google Cloud Vertex AI. Gemini models go through ``generateContent``; Claude models (``claude-*``) through
    ``rawPredict`` with the Anthropic Messages format.

    Project and location come from GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION (default ``global``).
    """

    name = "google"
    TOKEN_TTL_S = 45 * 60  # gcloud tokens last an hour

    def __init__(self, model: str = "claude-sonnet-5-5", *, project: str | None = None, location: str | None = None,
                 max_tokens: int = 2048, retries: int = 3, client: httpx.Client | None = None,
                 token: Callable[[], str] = gcloud_access_token):
        self.model, self.max_tokens, self.retries = model, max_tokens, retries
        self.project = project or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self.location = location or os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
        if not self.project:
            raise ValueError("Vertex AI needs a project: set GOOGLE_CLOUD_PROJECT")
        self._client = client or httpx.Client(timeout=120)
        self._token_fn, self._token, self._token_at = token, "", 0.0

    @property
    def claude(self) -> bool:
        return self.model.startswith("claude")

    def url(self) -> str:
        host = "aiplatform.googleapis.com" if self.location == "global" else f"{self.location}-aiplatform.googleapis.com"
        publisher, method = ("anthropic", "rawPredict") if self.claude else ("google", "generateContent")
        return (f"https://{host}/v1/projects/{self.project}/locations/{self.location}/publishers/{publisher}"
                f"/models/{self.model}:{method}")

    def _headers(self) -> dict:
        if not self._token or time.monotonic() - self._token_at > self.TOKEN_TTL_S:
            self._token, self._token_at = self._token_fn(), time.monotonic()
        return {"Authorization": f"Bearer {self._token}", "content-type": "application/json"}

    # Gemini returns an opaque thought signature with function calls that must be sent back on the next turn.
    # The transcript only keeps a call's id, name and arguments, so the signature rides in the id.
    SIG = "~"

    @classmethod
    def to_wire(cls, messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "parts": [{"text": m["content"]}]})
            elif m["role"] == "assistant":
                parts: list[dict] = [{"text": m["content"]}] if m.get("content") else []
                for tc in m.get("tool_calls") or []:
                    part: dict[str, Any] = {"functionCall": {"name": tc.name, "args": tc.arguments}}
                    _, sep, sig = tc.id.partition(cls.SIG)
                    if sep and sig:
                        part["thoughtSignature"] = sig
                    parts.append(part)
                out.append({"role": "model", "parts": parts or [{"text": ""}]})
            elif m["role"] == "tool":
                part = {"functionResponse": {"name": m["name"],
                                             "response": {"error" if m.get("is_error") else "content": m["content"]}}}
                # Consecutive tool results belong in one user turn.
                if out and out[-1]["role"] == "user" and "functionResponse" in out[-1]["parts"][0]:
                    out[-1]["parts"].append(part)
                else:
                    out.append({"role": "user", "parts": [part]})
        return out

    def complete(self, system: str, messages: list[dict], tools: Sequence[ToolSpec]) -> LLMResponse:
        if self.claude:
            body: dict[str, Any] = {"anthropic_version": "vertex-2023-10-16", "max_tokens": self.max_tokens,
                                    "system": system, "messages": AnthropicLLM.to_wire(messages)}
            if tools:
                body["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.parameters}
                                 for t in tools]
            started = time.perf_counter()
            data = _post_with_retry(self._client, self.url(), self._headers(), body, self.retries)
            return AnthropicLLM.parse(data, self.model, started)
        body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": self.to_wire(messages),
                "generationConfig": {"maxOutputTokens": self.max_tokens}}
        if tools:
            decls = []
            for t in tools:
                d: dict[str, Any] = {"name": t.name, "description": t.description}
                if t.parameters.get("properties"):  # Gemini rejects an object schema with no properties
                    d["parameters"] = t.parameters
                decls.append(d)
            body["tools"] = [{"functionDeclarations": decls}]
        started = time.perf_counter()
        data = _post_with_retry(self._client, self.url(), self._headers(), body, self.retries)
        try:
            cand = data["candidates"][0]
        except (KeyError, IndexError) as exc:
            reason = (data.get("promptFeedback") or {}).get("blockReason", "no candidates")
            raise LLMError(f"Gemini returned no answer: {reason}") from exc
        text, calls = [], []
        for part in (cand.get("content") or {}).get("parts") or []:
            if "functionCall" in part:
                fc = part["functionCall"]
                sig = part.get("thoughtSignature")
                cid = f"g{uuid.uuid4().hex[:10]}" + (f"{self.SIG}{sig}" if sig else "")
                args = fc.get("args")
                calls.append(ToolCall(cid, fc.get("name", ""), args if isinstance(args, dict) else {}))
            elif "text" in part and not part.get("thought"):
                text.append(part["text"])
        usage = data.get("usageMetadata") or {}
        return LLMResponse("".join(text), calls, cand.get("finishReason", ""), int(usage.get("promptTokenCount") or 0),
                           int(usage.get("candidatesTokenCount") or 0) + int(usage.get("thoughtsTokenCount") or 0),
                           data.get("modelVersion", self.model), (time.perf_counter() - started) * 1000)


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
    if provider == "google":
        return VertexLLM(model or "claude-sonnet-5-5", **kwargs)
    raise ValueError(f"unknown provider '{provider}' (anthropic | openai | google)")
