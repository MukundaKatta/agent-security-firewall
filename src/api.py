"""FastAPI surface for the legacy inbound-only check.

Install with the optional [api] extra:
    pip install -e ".[api]"
"""
from fastapi import FastAPI
from pydantic import BaseModel

from .firewall import AgentFirewall

app = FastAPI(title="Agent Security Firewall", version="0.2.0")
firewall = AgentFirewall()


class CheckRequest(BaseModel):
    agent_id: str
    input_text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/check")
def check_input(req: CheckRequest):
    decision = firewall.check_input(req.agent_id, req.input_text)
    return decision.model_dump()


@app.get("/audit")
def audit_log():
    return [e.model_dump() for e in firewall.audit.get_entries()]
