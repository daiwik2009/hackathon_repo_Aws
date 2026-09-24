import sys
import json


# Signals that indicate a stronger mismatch between
# what the user/agent expects and what will happen.
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
}


def calculate_finding_risk(finding):
    """
    Recalculate risk from the detector's evidence.

    Keeping this logic here means detectors can provide
    evidence without making the final security decision.
    """

    signals = set(finding.get("signals", []))

    score = 0

    # Strong intent mismatch.
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

    return score, decision


def build_reason(signals):
    """
    Turn technical signals into human-readable explanations.
    """

    reasons = []

    explanations = {
        "download_action_leads_to_subscription":
            "A download action appears to lead to a subscription flow.",

        "download_action_leads_to_payment":
            "A download action appears to lead to a payment flow.",

        "close_action_leads_to_subscription":
            "A close/dismiss action appears to lead to a subscription flow.",

        "close_action_leads_to_payment":
            "A close/dismiss action appears to lead to a payment flow.",

        "download_action_leads_to_login":
            "A download action appears to lead to a login page.",

        "close_action_leads_to_login":
            "A close/dismiss action appears to lead to a login page.",

        "continue_action_leads_to_payment":
            "A generic continue action appears to lead to payment.",

        "redirect_parameter":
            "The destination contains a parameter commonly used for redirects.",

        "cross_domain_destination":
            "The action navigates to a different domain.",
    }

    for signal in signals:

        explanation = explanations.get(signal)

        if explanation:
            reasons.append(explanation)

    return reasons


def evaluate_finding(finding):
    """
    Convert a detector finding into a Bodyguard decision.
    """

    score, decision = calculate_finding_risk(
        finding
    )

    signals = finding.get(
        "signals",
        []
    )

    return {
        "element_type": finding.get(
            "element_type"
        ),

        "text": finding.get(
            "text"
        ),

        "destination": finding.get(
            "destination"
        ),

        "decision": decision,

        "risk_score": score,

        "signals": signals,

        "reasons": build_reason(
            signals
        ),
    }


def evaluate_page(analysis):
    """
    Evaluate all findings from the detector.
    """

    findings = analysis.get(
        "findings",
        []
    )

    evaluated = []

    for finding in findings:

        evaluated.append(
            evaluate_finding(
                finding
            )
        )

    # Highest risk first.
    evaluated.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    # Determine overall page decision.
    if any(
        item["decision"] == "BLOCK"
        for item in evaluated
    ):
        overall_decision = "BLOCK"

    elif any(
        item["decision"] == "WARN"
        for item in evaluated
    ):
        overall_decision = "WARN"

    else:
        overall_decision = "ALLOW"

    highest_score = max(
        (
            item["risk_score"]
            for item in evaluated
        ),
        default=0
    )

    return {
        "page": analysis.get(
            "page",
            {}
        ),

        "overall_decision": overall_decision,

        "highest_risk_score": highest_score,

        "findings": evaluated,
    }


def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python analyser.py <analysis.json>"
        )

        sys.exit(1)

    filename = sys.argv[1]

    try:

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

            analysis = json.load(file)

        result = evaluate_page(
            analysis
        )

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False
            )
        )

    except FileNotFoundError:

        print(
            f"File not found: {filename}"
        )

        sys.exit(1)

    except json.JSONDecodeError:

        print(
            "Invalid JSON file."
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
