"""Interactive local reviewer; displayed previews must be handled as sensitive data."""
def cli_approver(packet, timeout_seconds):
    print(packet.explanation)
    print(f"Tool: {packet.tool}; review values: {packet.values_preview}")
    answer=input("Approve this exact call? [y/N] ").strip().casefold()
    return answer == "y"
