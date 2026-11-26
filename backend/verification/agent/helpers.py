import json
from collections.abc import Callable
from typing import Any

import httpx2

from app.agent import DiagnosisAgent
from verification.engine.helpers import FAKE_KEY, ai_settings, draft, tool_evidence

Messages = list[dict[str, Any]]


def call(name: str, **arguments: Any) -> dict:
    return {"tool_calls": [(name, arguments)]}


def raw_call(name: str, arguments: str) -> dict:
    return {"tool_calls": [(name, arguments)]}


def answer(payload: dict | str | Callable[[Messages], dict | str]) -> dict:
    return {"answer": payload}


def status(code: int, body: Any = None) -> dict:
    return {"status": code, "body": body if body is not None else {"error": {"message": "failure"}}}


def cite(*codes: str, **overrides: Any) -> Callable[[Messages], dict]:
    def build(messages: Messages) -> dict:
        ids = [evidence for code in codes for evidence in tool_evidence(messages, code)]
        return draft(supporting_evidence_ids=ids, **overrides)
    return build


def completion(message: dict, finish: str) -> dict:
    return {"id": "chatcmpl-test", "object": "chat.completion", "created": 0, "model": "approved-test-model",
            "choices": [{"index": 0, "finish_reason": finish, "message": message}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


class ScriptedModel:
    def __init__(self, steps: list[Any]) -> None:
        self.steps = list(steps)
        self.requests: list[dict] = []
        self.headers: list[dict] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        self.headers.append(dict(request.headers))
        step = self.steps.pop(0) if self.steps else answer("no further scripted output")
        if isinstance(step, BaseException):
            raise step
        if "status" in step:
            return httpx2.Response(step["status"], json=step["body"])
        if "raw" in step:
            return httpx2.Response(200, content=step["raw"])
        if "tool_calls" in step:
            calls = [{"id": f"call-{len(self.requests)}-{index}", "type": "function",
                      "function": {"name": name, "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments)}}
                     for index, (name, arguments) in enumerate(step["tool_calls"])]
            return httpx2.Response(200, json=completion({"role": "assistant", "content": None, "tool_calls": calls}, "tool_calls"))
        payload = step["answer"]
        if callable(payload):
            payload = payload(body["messages"])
        content = payload if isinstance(payload, str) else json.dumps(payload)
        return httpx2.Response(200, json=completion({"role": "assistant", "content": content}, "stop"))

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self.handler))

    def tool_messages(self) -> list[str]:
        return [m["content"] for m in self.requests[-1]["messages"] if m["role"] == "tool"] if self.requests else []

    def sent_text(self) -> str:
        return json.dumps(self.requests)


def scripted_agent(steps: list[Any], **settings: Any) -> tuple[DiagnosisAgent, ScriptedModel]:
    model = ScriptedModel(steps)
    return DiagnosisAgent(settings=ai_settings(**settings), http_client=model.client()), model


__all__ = ["FAKE_KEY", "ScriptedModel", "answer", "call", "cite", "raw_call", "scripted_agent", "status"]
