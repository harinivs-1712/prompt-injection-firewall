"""Temporary-directory tools that record names only, never argument values."""
from pathlib import Path


def make_logging_tool(name, log_path):
    if not isinstance(name, str) or not name:
        raise ValueError("tool name must be non-empty")
    target = Path(log_path)

    def invoke(**kwargs):
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as stream:
            stream.write(f"{name} ({', '.join(sorted(kwargs))})\n")
        return {"tool": name, "argument_names": sorted(kwargs)}

    return invoke


def build_tools(policy, temp_dir):
    return {name: make_logging_tool(name, Path(temp_dir) / "tool_calls.log") for name in policy.tools}


def make_email_example_tools(temp_dir):
    """Optional named examples; production harness construction remains policy-driven."""
    names = ("read_email", "search_notes", "send_email", "make_payment")
    return {name: make_logging_tool(name, Path(temp_dir) / "tool_calls.log") for name in names}
