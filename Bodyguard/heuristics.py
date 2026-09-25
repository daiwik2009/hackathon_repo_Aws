"""
AI Bodyguard - shared pipeline heuristics.

Previously `should_use_dynamic` was defined only inside app.py, so
investigator.py had no way to reuse it and instead ran the (expensive,
Playwright/Chromium-backed) dynamic scanner unconditionally on every
URL it investigated -- including every recursively discovered child
URL. Centralising the heuristic here means both entry points agree on
when dynamic inspection is actually warranted.
"""

from __future__ import annotations

from typing import Any, Dict


def should_use_dynamic(scan_result: Dict[str, Any]) -> bool:
    """
    Decide whether a page should receive browser-based dynamic
    inspection, based on the static scan's findings.

    Temporary v0.2 heuristic (inherited as-is from app.py): triggers
    on the mere presence of any script or inline JS handler. Since
    that's true of most modern websites, this rarely actually skips
    the dynamic scan in practice -- tightening it (e.g. requiring a
    navigation-capable handler, an external script host, or a form
    with an empty/JS-driven action) is the next real improvement here,
    not something this pass attempts blindly.
    """

    scripts = scan_result.get("scripts", [])
    handlers = scan_result.get("javascript_handlers", [])

    return bool(scripts or handlers)
