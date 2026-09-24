"""
AI Bodyguard analyser.

Responsibility:
    Convert detector signals into risk scores and decisions.

Pipeline:

    scanner
       ↓
    detector
       ↓
    analyser
       ↓
    actions

Detector finds evidence.
Analyser interprets that evidence.
Actions decides what can actually be executed.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List


# ============================================================
# RISK SIGNALS
# ============================================================

HIGH_RISK_SIGNALS = {
    "download_action_leads_to_subscription",
    "download_action_leads_to_payment",
    "close_action_leads_to_subscription",
    "close_action_leads_to_payment",
}

MEDIUM_RISK_SIGNALS = {
    "download_action_leads_to_login",
    "close_action_leads_to_login",
    "continue_action_leads_to_payment",
    "javascript_navigation",
    "password_input",
    "payment_input",
    "redirect_parameter",
}

# Suspicious context signals (NOT dangerous by themselves)
LOW_RISK_SIGNALS = {
    "cross_domain_destination",
}


# ============================================================
# SIGNAL EXPLANATIONS
# ============================================================

SIGNAL_EXPLANATIONS = {
    "download_action_leads_to_subscription": (
        "A download-related action appears to lead to a subscription or membership destination."
    ),
    "download_action_leads_to_payment": (
        "A download-related action appears to lead to a payment or checkout destination."
    ),
    "close_action_leads_to_subscription": (
        "A close or dismiss action appears to lead to a subscription or membership destination."
    ),
    "close_action_leads_to_payment": (
        "A close or dismiss action appears to lead to a payment or checkout destination."
    ),
    "download_action_leads_to_login": (
        "A download-related action appears to lead to a login destination."
    ),
    "close_action_leads_to_login": (
        "A close or dismiss action appears to lead to a login destination."
    ),
    "continue_action_leads_to_payment": (
        "A continue action appears to lead to a payment or checkout destination."
    ),
    "redirect_parameter": (
        "The destination contains a parameter commonly associated with redirection."
    ),
    "cross_domain_destination": (
        "The action points to a different domain from the current page."
    ),
    "javascript_navigation": (
        "The element contains JavaScript capable of changing or opening navigation."
    ),
    "password_input": "The form requests password-related information.",
    "payment_input": "The form contains controls associated with payment information.",
}


# ============================================================
# SIGNAL WEIGHTS
# ============================================================

SIGNAL_WEIGHTS = {
    # High confidence intent mismatch
    "download_action_leads_to_subscription": 50,
    "download_action_leads_to_payment": 50,
    "close_action_leads_to_subscription": 50,
    "close_action_leads_to_payment": 50,
    # Medium confidence
    "download_action_leads_to_login": 30,
    "close_action_leads_to_login": 30,
    "continue_action_leads_to_payment": 30,
    "javascript_navigation": 30,
    "password_input": 30,
    "payment_input": 30,
    "redirect_parameter": 30,
    # Context only
    "cross_domain_destination": 10,
}


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_finding_risk(signals: List[str]) -> Dict[str, Any]:
    score = sum(SIGNAL_WEIGHTS.get(signal, 0) for signal in set(signals))
    score = min(score, 100)

    if score >= 70:
        decision = "BLOCK"
    elif score >= 30:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "risk_score": score,
        "decision": decision,
    }


# ============================================================
# REASON GENERATION
# ============================================================

def build_reason(signals: List[str]) -> List[str]:
    reasons = []
    for signal in set(signals):
        explanation = SIGNAL_EXPLANATIONS.get(signal)
        if explanation:
            reasons.append(explanation)
        else:
            reasons.append(f"Detected security signal: {signal}")
    return reasons


# ============================================================
# FINDING EVALUATION
# ============================================================

def evaluate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    signals = finding.get("signals", [])
    risk = calculate_finding_risk(signals)

    return {
        "element_type": finding.get("element_type"),
        "text": finding.get("text", ""),
        "destination": finding.get("destination"),
        "decision": risk["decision"],
        "risk_score": risk["risk_score"],
        "signals": signals,
        "reasons": build_reason(signals),
    }


# ============================================================
# PAGE EVALUATION
# ============================================================

def evaluate_page(analysis: Dict[str, Any]) -> Dict[str, Any]:
    findings = analysis.get("findings", [])
    evaluated_findings = [evaluate_finding(finding) for finding in findings]

    # Sort highest-risk findings first
    evaluated_findings.sort(
        key=lambda item: item.get("risk_score", 0),
        reverse=True,
    )

    # PAGE DECISION
    if any(finding["decision"] == "BLOCK" for finding in evaluated_findings):
        overall_decision = "BLOCK"
    elif any(finding["decision"] == "WARN" for finding in evaluated_findings):
        overall_decision = "WARN"
    else:
        overall_decision = "ALLOW"

    highest_risk = (
        evaluated_findings[0]["risk_score"] if evaluated_findings else 0
    )

    return {
        "page": analysis.get("page", {}),
        "overall_decision": overall_decision,
        "risk_score": highest_risk,
        "findings": evaluated_findings,
    }


# ============================================================
# JSON HELPERS
# ============================================================

def load_analysis(filename: str = "analysis.json") -> Dict[str, Any]:
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def save_analyser_output(
    result: Dict[str, Any], filename: str = "analyser.json"
) -> None:
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


# ============================================================
# CLI
# ============================================================

def main() -> None:
    input_file = sys.argv[1] if len(sys.argv) > 1 else "analysis.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "analyser.json"

    try:
        analysis = load_analysis(input_file)
        result = evaluate_page(analysis)
        save_analyser_output(result, output_file)

        print(json.dumps(result, indent=2, ensure_ascii=False))

    except FileNotFoundError:
        print(f"File not found: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Invalid JSON file: {input_file}")
        sys.exit(1)
    except Exception as error:
        print(f"Analyser error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()