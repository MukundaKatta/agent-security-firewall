"""FastAPI application."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .firewall import AgentFirewall

app = FastAPI(title="Agent Security Firewall", version="0.1.0")
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
    return firewall.audit_log
