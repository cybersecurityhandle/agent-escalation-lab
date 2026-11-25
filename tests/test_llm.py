"""Backends: message conversion and failure handling, without any network."""

import json
from types import SimpleNamespace as NS

import httpx
import pytest

from agent.llm import LLMError, LLMSettings, Message, ToolCall, ToolResult, ToolSpec, make_llm
from agent.llm.ollama_backend import OllamaLLM
from agent.llm.scripted import ScriptedLLM

TOOLS = [ToolSpec("t", "d", {"type": "object", "properties": {}})]


def history(raw):
    return [
        Message("user", "hi"),
        Message("assistant", "", [ToolCall("c1", "t", {})], raw=raw),
        Message("tool", results=[ToolResult("c1", "t", "out", True)]),
    ]


class FakeAnthropic:
    def __init__(self, response):
        self.requests, self.messages = [], self
        self._response = response

    def create(self, **kwargs):
        self.requests.append(kwargs)
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def anthropic_llm(response, model="m"):
    pytest.importorskip("anthropic")
    from agent.llm.anthropic_backend import AnthropicLLM

    client = FakeAnthropic(response)
    return AnthropicLLM(model, client), client


def test_anthropic_request_and_reply():
    content = [
        NS(type="thinking"),
        NS(type="text", text="hello"),
        NS(type="tool_use", id="c2", name="t", input={"a": 1}),
    ]
    llm, client = anthropic_llm(NS(stop_reason="tool_use", content=content))
    raw = [NS(type="thinking"), NS(type="tool_use", id="c1", name="t", input={})]
    reply = llm.complete("sys", history(raw), TOOLS)
    assert (reply.text, reply.tool_calls, reply.raw) == ("hello", [ToolCall("c2", "t", {"a": 1})], content)
    sent = client.requests[0]
    assert sent["messages"][1]["content"] is raw  # replayed unchanged, thinking included
    result = sent["messages"][2]["content"][0]
    assert (result["type"], result["tool_use_id"], result["is_error"]) == ("tool_result", "c1", True)
    assert sent["tools"][0]["input_schema"] == TOOLS[0].parameters and "tool_choice" not in sent


def test_anthropic_refusal_is_recorded_and_truncation_is_an_error():
    llm, _ = anthropic_llm(NS(stop_reason="refusal", content=[]))
    assert llm.complete("s", [Message("user", "x")], TOOLS).refused
    llm, _ = anthropic_llm(NS(stop_reason="max_tokens", content=[]))
    with pytest.raises(LLMError):
        llm.complete("s", [Message("user", "x")], TOOLS)


def test_anthropic_without_credentials_gives_a_clear_error():
    llm, _ = anthropic_llm(TypeError("Could not resolve authentication method"))
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        llm.complete("s", [Message("user", "x")], TOOLS)


def test_ollama_round_trip():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": "t", "arguments": {"a": 1}}}],
                }
            },
        )

    llm = OllamaLLM("m", httpx.Client(transport=httpx.MockTransport(handler), base_url="http://ollama"))
    reply = llm.complete("sys", history({"role": "assistant", "content": ""}), TOOLS)
    assert reply.tool_calls[0].args == {"a": 1}
    assert [m["role"] for m in seen["messages"]] == ["system", "user", "assistant", "tool"]


def test_ollama_errors_are_wrapped():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)), base_url="http://ollama")
    with pytest.raises(LLMError):
        OllamaLLM("m", client).complete("s", [Message("user", "x")], TOOLS)


def test_scripted_templates_take_values_from_the_context():
    script = {
        "benign": [
            {"tool": "t", "args": {"a": "{{find:K-[0-9]+}}", "b": "{{urlfind:K .}}"}},
            {"tool": "skipped", "if": "absent"},
            {"final": "{{find:nothing}}end"},
        ]
    }
    llm = ScriptedLLM(script)
    messages = [Message("user", "K-1 and K-2 and K x")]
    assert llm.complete("", messages, []).tool_calls[0].args == {"a": "K-1,K-2", "b": "K%20x"}
    assert llm.complete("", messages, []).text == "end"


def test_backend_selection():
    with pytest.raises(LLMError):
        make_llm(LLMSettings("nope"))
    with pytest.raises(LLMError):
        make_llm(LLMSettings("scripted"))
