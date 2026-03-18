"""Audit trail logging for all firewall decisions."""
import json, time, logging
from typing import Dict, List, Optional
from pathlib import Path
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class AuditEntry(BaseModel):
    timestamp: float
    agent_id: str
    action: str
    allowed: bool
    reason: str
    injection_score: float = 0.0
    anomaly_score: float = 0.0
    exfiltration_score: float = 0.0
    escalation_score: float = 0.0
    input_preview: str = ""

class AuditTrail:
    def __init__(self, log_dir: str = "~/.agent-firewall/audit"):
        self.log_dir = Path(log_dir).expanduser()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._entries: List[AuditEntry] = []

    def record(self, agent_id: str, allowed: bool, reason: str,
               input_text: str = "", **scores) -> AuditEntry:
        entry = AuditEntry(
            timestamp=time.time(), agent_id=agent_id, action="check_input",
            allowed=allowed, reason=reason,
            input_preview=input_text[:200], **scores)
        self._entries.append(entry)
        if not allowed:
            logger.warning(f"BLOCKED agent={agent_id}: {reason}")
        return entry

    def get_entries(self, agent_id: Optional[str] = None, limit: int = 100) -> List[AuditEntry]:
        entries = self._entries
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        return entries[-limit:]

    def get_stats(self) -> Dict:
        total = len(self._entries)
        blocked = sum(1 for e in self._entries if not e.allowed)
        return {"total": total, "blocked": blocked, "allowed": total - blocked,
                "block_rate": round(blocked / max(total, 1), 3)}

    def save(self) -> str:
        path = self.log_dir / f"audit_{int(time.time())}.json"
        data = [e.model_dump() for e in self._entries]
        path.write_text(json.dumps(data, indent=2))
        return str(path)
