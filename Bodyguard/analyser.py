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
    "credential_submission_to_external_domain",
    "payment_submission_to_external_domain",
    "javascript_url",
    "data_url",
    "vbscript_url",
}

MEDIUM_RISK_SIGNALS = {
    "download_action_leads_to_login",
    "close_action_leads_to_login",
    "continue_action_leads_to_payment",
    "continue_action_leads_to_subscription",
    "continue_action_leads_to_login",
    "download_action_leads_to_redirect",
    "login_to_external_domain",
    "payment_to_external_domain",
    "download_to_external_domain",
    "javascript_navigation",
    "dynamic_navigation",
    "dynamic_code_execution",
    "dynamic_javascript_execution",
    "password_input",
    "payment_input",
    "identity_input",
    "sensitive_data_via_get",
    "payment_data_via_get",
    "redirect_parameter",
}

# Contextual signals (NOT dangerous by themselves)
LOW_RISK_SIGNALS = {
    "cross_domain_destination",
}


# ============================================================
# SIGNAL EXPLANATIONS
# ============================================================

SIGNAL_EXPLANATIONS = {
    # INTENT MISMATCH
    "download_action_leads_to_subscription": (
        "A download-related action appears to lead to a subscription or membership destination."
    ),
    "download_action_leads_to_payment": (
        "A download-related action appears to lead to a payment or checkout destination."
    ),
    "download_action_leads_to_login": (
        "A download-related action appears to lead to a login destination."
    ),
    "download_action_leads_to_redirect": (
        "A download-related action appears to lead through a redirect-style destination."
    ),
    "close_action_leads_to_subscription": (
        "A close or dismiss action appears to lead to a subscription or membership destination."
    ),
    "close_action_leads_to_payment": (
        "A close or dismiss action appears to lead to a payment or checkout destination."
    ),
    "close_action_leads_to_login": (
        "A close or dismiss action appears to lead to a login destination."
    ),
    "continue_action_leads_to_payment": (
        "A continue action appears to lead to a payment or checkout destination."
    ),
    "continue_action_leads_to_subscription": (
        "A continue action appears to lead to a subscription or membership destination."
    ),
    "continue_action_leads_to_login": (
        "A continue action appears to lead to a login destination."
    ),
    # EXTERNAL DESTINATIONS
    "cross_domain_destination": (
        "The action points to a different domain from the current page."
    ),
    "login_to_external_domain": (
        "A login-related action points to a different domain."
    ),
    "payment_to_external_domain": (
        "A payment-related action points to a different domain."
    ),
    "download_to_external_domain": (
        "A download-related action points to a different domain."
    ),
    # REDIRECTS
    "redirect_parameter": (
        "The destination contains a parameter commonly associated with redirection."
    ),
    # JAVASCRIPT
    "javascript_navigation": (
        "The element contains JavaScript capable of changing or opening navigation."
    ),
    "dynamic_navigation": "The element uses dynamic JavaScript navigation.",
    "dynamic_code_execution": "The element contains a dynamic code execution pattern.",
    "dynamic_javascript_execution": "The element uses dynamically scheduled JavaScript.",
    "javascript_url": "The destination uses a javascript: URL scheme.",
    "data_url": "The destination uses a data: URL scheme.",
    "vbscript_url": "The destination uses a vbscript: URL scheme.",
    # SENSITIVE INPUT
    "password_input": "The form requests password-related information.",
    "identity_input": (
        "The form requests identity-related information such as an email address or username."
    ),
    "payment_input": "The form contains controls associated with payment information.",
    "credential_submission_to_external_domain": (
        "Credential-related information appears to be submitted to a different domain."
    ),
    "payment_submission_to_external_domain": (
        "Payment-related information appears to be submitted to a different domain."
    ),
    "sensitive_data_via_get": (
        "Sensitive information appears to be submitted using the GET method."
    ),
    "payment_data_via_get": (
        "Payment-related information appears to be submitted using the GET method."
    ),
}


# ============================================================
# SIGNAL WEIGHTS
# ============================================================

SIGNAL_WEIGHTS = {
    # VERY STRONG EVIDENCE
    "download_action_leads_to_subscription": 55,
    "download_action_leads_to_payment": 55,
    "close_action_leads_to_subscription": 55,
    "close_action_leads_to_payment": 55,
    "credential_submission_to_external_domain": 65,
    "payment_submission_to_external_domain": 70,
    "javascript_url": 70,
    "data_url": 65,
    "vbscript_url": 70,

    # STRONG / MEDIUM EVIDENCE
    "download_action_leads_to_login": 30,
    "close_action_leads_to_login": 30,
    "continue_action_leads_to_payment": 35,
    "continue_action_leads_to_subscription": 30,
    "continue_action_leads_to_login": 25,
    "download_action_leads_to_redirect": 30,
    "login_to_external_domain": 25,
    "payment_to_external_domain": 35,
    "download_to_external_domain": 20,
    "javascript_navigation": 20,
    "dynamic_navigation": 15,
    "dynamic_code_execution": 35,
    "dynamic_javascript_execution": 15,
    "password_input": 15,
    "payment_input": 25,
    "identity_input": 5,
    "sensitive_data_via_get": 25,
    "payment_data_via_get": 35,
    "redirect_parameter": 20,

    # CONTEXT ONLY
    "cross_domain_destination": 5,
}


# ============================================================
# SIGNAL GROUPS
# ============================================================

# Signals in these groups overlap conceptually.
# This prevents the analyser from excessively inflating scores.

SIGNAL_GROUPS = {
    "external_domain": {
        "cross_domain_destination",
        "login_to_external_domain",
        "payment_to_external_domain",
        "download_to_external_domain",
    },
    "javascript_navigation": {
        "javascript_navigation",
        "dynamic_navigation",
    },
    "dynamic_execution": {
        "dynamic_code_execution",
        "dynamic_javascript_execution",
    },
    "sensitive_credentials": {
        "password_input",
        "identity_input",
        "credential_submission_to_external_domain",
    },
    "payment": {
        "payment_input",
        "payment_to_external_domain",
        "payment_submission_to_external_domain",
        "payment_data_via_get",
    },
}


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_finding_risk(signals: List[str]) -> Dict[str, Any]:
    unique_signals = set(signals)

    # Sort signals by weight (highest weight first) to give priority
    # to stronger evidence when resolving overlapping signal groups.
    sorted_signals = sorted(
        unique_signals,
        key=lambda s: SIGNAL_WEIGHTS.get(s, 0),
        reverse=True
    )

    score = 0
    counted_groups = set()

    # Base signal scoring
    for signal in sorted_signals:
        weight = SIGNAL_WEIGHTS.get(signal, 0)
        if weight <= 0:
            continue

        belonging_groups = [
            group_name
            for group_name, group_signals in SIGNAL_GROUPS.items()
            if signal in group_signals
        ]

        if belonging_groups:
            if any(group_name in counted_groups for group_name in belonging_groups):
                continue
            for group_name in belonging_groups:
                counted_groups.add(group_name)

        score += weight

    # Combination bonuses
    if "cross_domain_destination" in unique_signals and "password_input" in unique_signals:
        score += 15

    if "payment_input" in unique_signals and "cross_domain_destination" in unique_signals:
        score += 15

    if "redirect_parameter" in unique_signals and "cross_domain_destination" in unique_signals:
        score += 10

    if "javascript_navigation" in unique_signals and "redirect_parameter" in unique_signals:
        score += 15

    if "download_to_external_domain" in unique_signals and "redirect_parameter" in unique_signals:
        score += 15

    # Score Cap
    score = min(score, 100)

    # Decision thresholds
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
    for signal in sorted(set(signals)):
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
        "intent": finding.get("intent", []),
        "destination_types": finding.get("destination_types", []),
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

    # Page Decision
    if any(finding["decision"] == "BLOCK" for finding in evaluated_findings):
        overall_decision = "BLOCK"
    elif any(finding["decision"] == "WARN" for finding in evaluated_findings):
        overall_decision = "WARN"
    else:
        overall_decision = "ALLOW"

    highest_risk = evaluated_findings[0]["risk_score"] if evaluated_findings else 0

    block_count = sum(1 for f in evaluated_findings if f["decision"] == "BLOCK")
    warn_count = sum(1 for f in evaluated_findings if f["decision"] == "WARN")
    allow_count = sum(1 for f in evaluated_findings if f["decision"] == "ALLOW")

    return {
        "page": analysis.get("page", {}),
        "overall_decision": overall_decision,
        "risk_score": highest_risk,
        "finding_counts": {
            "block": block_count,
            "warn": warn_count,
            "allow": allow_count,
            "total": len(evaluated_findings),
        },
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