"""CLI for agent-security-firewall.

Three subcommands map to the three modes:

    python -m src inbound   --agent a1 --text "ignore previous instructions"
    python -m src tool      --agent a1 --tool tools.shell.bash --args "rm -rf /"
    python -m src status
"""
from __future__ import annotations

import argparse
import json
import sys

from .firewall import Firewall


def _print(obj):
    print(json.dumps(obj, indent=2, default=str))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-security-firewall",
        description="Inbound + tool-call security firewall for AI agents.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_in = sub.add_parser("inbound", help="check untrusted text the model is about to read")
    p_in.add_argument("--agent", default="cli-agent")
    p_in.add_argument("--text", required=True)

    p_tc = sub.add_parser("tool", help="check a proposed tool call")
    p_tc.add_argument("--agent", default="cli-agent")
    p_tc.add_argument("--tool", required=True, help="dotted tool path, e.g. tools.shell.bash")
    p_tc.add_argument("--args", default="", help="raw arg string passed to the sandbox checker")

    sub.add_parser("status", help="print firewall metadata")

    args = parser.parse_args(argv)
    fw = Firewall()

    if args.cmd == "inbound":
        result = fw.check_inbound(args.agent, args.text)
        _print(
            {
                "mode": result.mode,
                "allowed": result.allowed,
                "reason": result.reason,
                "elapsed_ms": result.elapsed_ms,
            }
        )
        return 0 if result.allowed else 1

    if args.cmd == "tool":
        # Auto-register a vanilla agent so the demo works without prior setup.
        fw.register_agent(args.agent)
        result = fw.check_tool_call(args.agent, args.tool, {"raw": args.args})
        _print(
            {
                "mode": result.mode,
                "allowed": result.allowed,
                "reason": result.reason,
                "elapsed_ms": result.elapsed_ms,
            }
        )
        return 0 if result.allowed else 1

    if args.cmd == "status":
        _print(
            {
                "service": "agent-security-firewall",
                "version": "0.2.0",
                "modes": ["inbound", "tool_call", "egress (delegated)"],
                "sibling": "https://github.com/MukundaKatta/agentguard (egress)",
            }
        )
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
