from __future__ import annotations

import json
import os
import uuid

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .audit import Auditor
from .policy import GuardrailPolicy
from .scanner import sanitize_json


class GuardrailMiddleware:
    """Bidirectional JSON guardrails with privacy-safe, policy-versioned audit events."""

    def __init__(self, app: ASGIApp, mode: str | None = None, audit_key: str | None = None,
                 max_body_bytes: int | None = None, policy: GuardrailPolicy | None = None):
        self.app = app
        self.policy = policy or GuardrailPolicy.from_env(mode, max_body_bytes)
        self.auditor = Auditor(
            audit_key or os.getenv("GUARDRAIL_AUDIT_KEY", "development-only-key"),
            self.policy.version,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or scope.get("path") in self.policy.excluded_paths:
            return await self.app(scope, receive, send)
        headers = MutableHeaders(scope=scope)
        request_id = headers.get("x-request-id", str(uuid.uuid4()))
        headers["x-request-id"] = request_id
        if "application/json" not in headers.get("content-type", ""):
            return await self.app(scope, receive, self._request_id_sender(send, request_id))

        body = await self._read_body(receive)
        if len(body) > self.policy.max_body_bytes:
            self._audit("input_blocked", request_id, body, (), "input", "block")
            return await self._error(413, "request_too_large", request_id, send, scope)
        try:
            payload = json.loads(body or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return await self._error(400, "invalid_json", request_id, send, scope)

        sanitized_payload, input_findings = sanitize_json(payload)
        if input_findings:
            action = "block" if self.policy.should_block(input_findings, "input") else "sanitize"
            self._audit("input_evaluated", request_id, body, input_findings, "input", action)
            if action == "block":
                return await self._error(422, "input_rejected", request_id, send, scope)
        sanitized = json.dumps(sanitized_payload, ensure_ascii=False, separators=(",", ":")).encode()

        sent = False
        async def replay() -> Message:
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": sanitized, "more_body": False}

        response_start: Message | None = None
        response_body = bytearray()
        capture_json = False
        async def capture(message: Message):
            nonlocal response_start, capture_json
            if message["type"] == "http.response.start":
                response_start = message
                response_headers = MutableHeaders(raw=message["headers"])
                capture_json = "application/json" in response_headers.get("content-type", "")
                if not capture_json:
                    response_headers["x-request-id"] = request_id
                    response_headers["x-guardrail-policy"] = self.policy.version
                    await send(message)
                return
            if message["type"] != "http.response.body":
                return await send(message)
            if not capture_json:
                return await send(message)
            response_body.extend(message.get("body", b""))
            if message.get("more_body", False):
                return
            rendered = bytes(response_body)
            output_findings = ()
            try:
                output_payload = json.loads(rendered or b"{}")
                output_payload, output_findings = sanitize_json(output_payload)
                rendered = json.dumps(output_payload, ensure_ascii=False, separators=(",", ":")).encode()
            except (json.JSONDecodeError, UnicodeDecodeError):
                output_findings = ()
            if output_findings:
                action = "block" if self.policy.should_block(output_findings, "output") else "sanitize"
                self._audit("output_evaluated", request_id, bytes(response_body), output_findings, "output", action)
                if action == "block":
                    return await self._error(502, "unsafe_model_output", request_id, send, scope)
            if response_start:
                mutable = MutableHeaders(raw=response_start["headers"])
                mutable["content-length"] = str(len(rendered))
                mutable["x-request-id"] = request_id
                mutable["x-guardrail-policy"] = self.policy.version
                await send(response_start)
            await send({"type": "http.response.body", "body": rendered, "more_body": False})

        await self.app(scope, replay, capture)

    def _audit(self, name, request_id, content, findings, direction, action):
        self.auditor.emit(self.auditor.event(name, request_id, content, findings, direction, action))

    async def _error(self, status, code, request_id, send, scope):
        response = JSONResponse({"error": {"code": code, "request_id": request_id}}, status)
        response.headers["x-request-id"] = request_id
        response.headers["x-guardrail-policy"] = self.policy.version
        return await response(scope, self._empty_receive, send)

    @staticmethod
    async def _empty_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    @staticmethod
    def _request_id_sender(send: Send, request_id: str):
        async def sender(message: Message):
            if message["type"] == "http.response.start":
                MutableHeaders(raw=message["headers"])["x-request-id"] = request_id
            await send(message)
        return sender

    async def _read_body(self, receive: Receive) -> bytes:
        chunks = bytearray()
        while True:
            message = await receive()
            chunks.extend(message.get("body", b""))
            if len(chunks) > self.policy.max_body_bytes:
                return bytes(chunks)
            if not message.get("more_body", False):
                return bytes(chunks)
