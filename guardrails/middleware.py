from __future__ import annotations

import json
import os
import uuid

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .audit import Auditor
from .scanner import scan


class GuardrailMiddleware:
    """Scan JSON inputs and outputs without retaining raw content in audit logs."""

    def __init__(self, app: ASGIApp, mode: str | None = None, audit_key: str | None = None,
                 max_body_bytes: int | None = None):
        self.app = app
        self.mode = mode or os.getenv("GUARDRAIL_MODE", "block")
        if self.mode not in {"block", "monitor"}:
            raise ValueError("GUARDRAIL_MODE must be block or monitor")
        self.max_body_bytes = max_body_bytes or int(os.getenv("GUARDRAIL_MAX_BODY_BYTES", "100000"))
        self.auditor = Auditor(audit_key or os.getenv("GUARDRAIL_AUDIT_KEY", "development-only-key"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = MutableHeaders(scope=scope)
        request_id = headers.get("x-request-id", str(uuid.uuid4()))
        headers["x-request-id"] = request_id
        content_type = headers.get("content-type", "")
        if "application/json" not in content_type:
            return await self.app(scope, receive, send)

        body = await self._read_body(receive)
        if len(body) > self.max_body_bytes:
            return await JSONResponse({"detail": "Request body exceeds guardrail limit"}, 413)(scope, receive, send)
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return await JSONResponse({"detail": "Invalid JSON"}, 400)(scope, receive, send)

        result = scan(json.dumps(payload, ensure_ascii=False))
        if result.blocked:
            self.auditor.emit(self.auditor.event("input_blocked", request_id, body, result.injection_rules, result.pii_types))
            if self.mode == "block":
                return await JSONResponse({"detail": "Input rejected by security policy", "request_id": request_id}, 422)(scope, receive, send)
        sanitized = result.text.encode()
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": sanitized, "more_body": False}

        response_start = None
        response_body = bytearray()

        async def capture(message: Message):
            nonlocal response_start
            if message["type"] == "http.response.start":
                response_start = message
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    output = scan(response_body.decode(errors="replace"))
                    rendered = output.text.encode()
                    if output.injection_rules or output.pii_types:
                        self.auditor.emit(self.auditor.event("output_sanitized", request_id, bytes(response_body), output.injection_rules, output.pii_types))
                    if response_start:
                        mutable = MutableHeaders(raw=response_start["headers"])
                        mutable["content-length"] = str(len(rendered))
                        mutable["x-request-id"] = request_id
                        await send(response_start)
                    await send({"type": "http.response.body", "body": rendered, "more_body": False})

        await self.app(scope, replay, capture)

    async def _read_body(self, receive: Receive) -> bytes:
        chunks = bytearray()
        while True:
            message = await receive()
            chunks.extend(message.get("body", b""))
            if not message.get("more_body", False):
                return bytes(chunks)
