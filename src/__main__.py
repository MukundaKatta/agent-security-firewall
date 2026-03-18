"""CLI for agent-security-firewall."""
import sys, json, argparse
from .core import AgentSecurityFirewall

def main():
    parser = argparse.ArgumentParser(description="Security middleware protecting AI agents from prompt injection and misalignment")
    parser.add_argument("command", nargs="?", default="status", choices=["status", "run", "info"])
    parser.add_argument("--input", "-i", default="")
    args = parser.parse_args()
    instance = AgentSecurityFirewall()
    if args.command == "status":
        print(json.dumps(instance.get_stats(), indent=2))
    elif args.command == "run":
        print(json.dumps(instance.process(input=args.input or "test"), indent=2, default=str))
    elif args.command == "info":
        print(f"agent-security-firewall v0.1.0 — Security middleware protecting AI agents from prompt injection and misalignment")

if __name__ == "__main__":
    main()
