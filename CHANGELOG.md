# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-05-24

### Changed
- Pivoted scope: this library is now the **inbound + tool-call** firewall sibling of
  [agentguard](https://github.com/MukundaKatta/agentguard) (egress). Egress is
  intentionally delegated to agentguard.
- Replaced the placeholder `AgentSecurityFirewall` core stub with a real
  `Firewall` facade that composes three modes: `inbound`, `tool_call`, and
  `egress` (egress hands off to a user-supplied callable, typically agentguard).
- License switched to MIT (was proprietary).
- README rewritten to explain how this differs from agentguard and shows
  a real attack scenario the firewall blocks end-to-end.

### Added
- `Firewall.check_inbound(agent_id, text)` — scrubs prompt injection, data
  exfiltration patterns, and privilege escalation requests in untrusted text
  the agent is about to consume.
- `Firewall.check_tool_call(agent_id, tool, args)` — validates each tool call
  against role-based access control, the action sandbox, and rate limits.
- `Firewall.check_egress(url, method, egress_check=...)` — optional pluggable
  egress hook; pairs cleanly with `agentguard.check`.
- `attack_scenarios` test module: three end-to-end attacks the firewall catches
  (indirect prompt injection from a fetched webpage, exfiltration tool combo,
  privilege escalation chain).
- Runnable `examples/firewall_demo.py` showing inbound + tool-call defense.

### Removed
- Stub `core.py` placeholder `AgentSecurityFirewall` class with synthetic
  `process/analyze/transform/...` methods.
- Generic `models.py` boilerplate that didn't represent any real domain object.
- Broken `examples/basic.py` (had an unterminated string).
- Proprietary copyright header from `LICENSE`.

### Fixed
- `test_anomaly_baseline` flake: the previous baseline required only 10 samples
  before scoring, which is too noisy. `AnomalyDetector` now needs at least
  `min_samples` (default 30) before it will mark anything anomalous.
- `test_firewall_blocks_injection` regex: the "you are now evil" prompt
  pattern was too narrow. Added a broader "you are now" rule.

## [0.1.0] - 2026-03-17

### Added
- Initial scaffold: detectors (injection, anomaly, exfiltration, escalation),
  policies (access control, rate limiter, action sandbox), FastAPI surface,
  audit trail.
