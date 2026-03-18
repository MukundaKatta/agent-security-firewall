"""Basic usage example for agent-security-firewall."""
from src.core import AgentSecurityFirewall

def main():
    instance = AgentSecurityFirewall(config={"verbose": True})

    print("=== agent-security-firewall Example ===\n")

    # Run primary operation
    result = instance.process(input="example data", mode="demo")
    print(f"Result: {result}")

    # Run multiple operations
    ops = ["process", "analyze", "transform]
    for op in ops:
        r = getattr(instance, op)(source="example")
        print(f"  {op}: {"✓" if r.get("ok") else "✗"}")

    # Check stats
    print(f"\nStats: {instance.get_stats()}")

if __name__ == "__main__":
    main()
