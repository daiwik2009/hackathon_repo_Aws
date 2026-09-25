"""
AI Bodyguard package.

Pipeline:
    static.scanner -> detector -> analyser -> actions
    (WARN pages only) -> investigator -> ai_analyser
"""

from Static.scanner import scan_page
from Dynamic import scan
from .detector import analyze_scan
from .analyser import evaluate_page
from .actions import build_action_plan
from .heuristics import should_use_dynamic
from url_safety import is_safe_url  # noqa: E402  (shared, project-root module)

# FIX: these existed in the codebase (investigator.py, ai_analyser.py)
# but were never exported from the package, so app.py had no way to
# import them without reaching into Bodyguard.investigator directly.
# That's the reason the live /scan endpoint never actually used the AI
# reasoning layer at all -- it was fully built but not wired in.
from .investigator import Investigator
from .ai_analyser import analyse as ai_analyse

__all__ = [
    "scan_page",
    "analyze_scan",
    "evaluate_page",
    "build_action_plan",
    "scan",
    "should_use_dynamic",
    "is_safe_url",
    "Investigator",
    "ai_analyse",
]

__version__ = "0.3.0"