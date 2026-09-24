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
    "redirect_parameter",
    "cross_domain_destination",

    # Added for the corrected detector.py
    "javascript_navigation",
    "password_input",
    "payment_input",
}


# ============================================================
# SIGNAL EXPLANATIONS
# ============================================================

SIGNAL_EXPLANATIONS = {
    "download_action_leads_to_subscription":
        "A download-related action appears to lead to a subscription or membership destination.",

    "download_action_leads_to_payment":
        "A download-related action appears to lead to a payment or checkout destination.",

    "close_action_leads_to_subscription":
        "A close or dismiss action appears to lead to a subscription or membership destination.",

    "close_action_leads_to_payment":
        "A close or dismiss action appears to lead to a payment or checkout destination.",

    "download_action_leads_to_login":
        "A download-related action appears to lead to a login destination.",

    "close_action_leads_to_login":
        "A close or dismiss action appears to lead to a login destination.",

    "continue_action_leads_to_payment":
        "A continue action appears to lead to a payment or checkout destination.",

    "redirect_parameter":
        "The destination contains parameters commonly associated with redirects.",

    "cross_domain_destination":
        "The action destination is on a different domain from the current page.",

    "javascript_navigation":
        "The action contains JavaScript navigation behavior.",

    "password_input":
        "The form contains a password input.",

    "payment_input":
        "The form contains an input associated with payment information.",
}


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_finding_risk(signals: List[str]) -> Dict[str, Any]:
    """
    Calculate the risk of one finding.

    Detector provides evidence/signals.
    Analyser is responsible for risk scoring and decisions.
    """

    score = 0

    for signal in signals:
        if signal in HIGH_RISK_SIGNALS:
            score += 50

        elif signal in MEDIUM_RISK_SIGNALS:
            score += 20

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
    """
    Convert detector signals into human-readable reasons.
    """

    reasons = []

    for signal in signals:
        explanation = SIGNAL_EXPLANATIONS.get(signal)

        if explanation:
            reasons.append(explanation)
        else:
            reasons.append(
                f"Detected security signal: {signal}"
            )

    return reasons


# ============================================================
# FINDING EVALUATION
# ============================================================

def evaluate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate one detector finding.
    """

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
    """
    Evaluate all findings on a page.

    Returns the final page-level security decision.
    """

    findings = analysis.get("findings", [])

    evaluated_findings = [
        evaluate_finding(finding)
        for finding in findings
    ]

    # Highest-risk findings first
    evaluated_findings.sort(
        key=lambda item: item.get("risk_score", 0),
        reverse=True,
    )

    # --------------------------------------------------------
    # Determine overall page decision
    # --------------------------------------------------------

    if any(
        finding["decision"] == "BLOCK"
        for finding in evaluated_findings
    ):
        overall_decision = "BLOCK"

    elif any(
        finding["decision"] == "WARN"
        for finding in evaluated_findings
    ):
        overall_decision = "WARN"

    else:
        overall_decision = "ALLOW"

    # Highest risk score on the page
    highest_risk = (
        evaluated_findings[0]["risk_score"]
        if evaluated_findings
        else 0
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
    """
    Load detector output from JSON.

    Mainly useful for CLI/debugging.
    app.py should normally pass dictionaries directly.
    """

    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def save_analyser_output(
    result: Dict[str, Any],
    filename: str = "analyser.json",
) -> None:
    """
    Save analyser output for debugging/export.
    """

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            result,
            file,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# CLI
# ============================================================

def main() -> None:
    """
    CLI usage:

        python analyser.py analysis.json analyser.json
    """

    input_file = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "analysis.json"
    )

    output_file = (
        sys.argv[2]
        if len(sys.argv) > 2
        else "analyser.json"
    )

    analysis = load_analysis(input_file)

    result = evaluate_page(analysis)

    save_analyser_output(
        result,
        output_file,
    )

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
