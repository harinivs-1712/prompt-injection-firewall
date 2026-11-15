"""Optional advisory task-fit checker interface."""
from typing import Protocol
class TaskFitChecker(Protocol):
    def check(self, user_task: str, tool_name: str, tool_description: str, arg_types: dict[str, str]) -> str: ...
class MockTaskFitChecker:
    def __init__(self, result="unknown"):
        self.result = result
        self.calls = []
    def check(self, user_task, tool_name, tool_description, arg_types):
        self.calls.append((user_task, tool_name, tool_description, dict(arg_types)))
        return self.result
