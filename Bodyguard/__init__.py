"""
AI Bodyguard package.

Pipeline:
    scanner -> detector -> analyser -> actions
"""

from .actions import (
    Action,
    ActionEngine,
    ActionType,
    build_action_plan,
    load_analysis,
    save_action_plan,
)

__all__ = [
    "Action",
    "ActionEngine",
    "ActionType",
    "build_action_plan",
    "load_analysis",
    "save_action_plan",
]

__version__ = "0.1.0"

