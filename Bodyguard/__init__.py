"""
AI Bodyguard package.

Pipeline:
    static.scanner -> detector -> analyser -> actions
"""

from static.scanner import scan_page
from .detector import analyze_scan
from .analyser import evaluate_page
from .actions import build_action_plan

__all__ = [
    "scan_page",
    "analyze_scan",
    "evaluate_page",
    "build_action_plan",
]

__version__ = "0.1.0"