from fastapi import FastAPI
from pydantic import BaseModel

from guardrails import GuardrailMiddleware

app = FastAPI(title="Guarded AI API", version="0.1.0")
app.add_middleware(GuardrailMiddleware)


class Message(BaseModel):
    prompt: str


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.post("/v1/echo")
def echo(message: Message):
    return {"answer": message.prompt}
