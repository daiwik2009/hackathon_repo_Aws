import sys
import json
import re
from urllib.parse import urlparse, parse_qs


# Words that describe common user intentions.
INTENT_KEYWORDS = {
    "download": [
        "download",
        "get file",
        "save file",
        "export",
        "pdf",
        "document",
    ],

    "close": [
        "close",
        "dismiss",
        "cancel",
        "no thanks",
        "exit",
    ],

    "continue": [
        "continue",
        "next",
        "proceed",
        "go ahead",
    ],

    "login": [
        "login",
        "log in",
        "sign in",
        "signin",
    ],

    "signup": [
        "sign up",
        "signup",
        "register",
        "create account",
    ],

    "payment": [
        "pay",
        "payment",
        "checkout",
        "purchase",
        "buy",
        "subscribe",
    ],
}


# Destination words that can indicate a different action.
DESTINATION_KEYWORDS = {
    "subscription": [
        "subscribe",
        "subscription",
        "membership",
        "plan",
        "pricing",
    ],

    "payment": [
        "payment",
        "checkout",
        "billing",
        "pay",
        "purchase",
        "order",
    ],

    "login": [
        "login",
        "signin",
        "sign-in",
        "authenticate",
    ],

    "download": [
        "download",
        "file",
        "export",
        "attachment",
    ],

    "account": [
        "account",
        "profile",
        "settings",
        "user",
    ],

    "redirect": [
        "redirect",
        "return",
        "continue",
        "goto",
        "next",
        "url=",
    ],
}


def normalize(text):
    """Normalize text for comparison."""

    if not text:
        return ""

    return " ".join(text.lower().split())


def classify_text(text):
    """
    Determine what a piece of text appears to be asking
    the user/agent to do.
    """

    text = normalize(text)

    detected = []

    for intent, keywords in INTENT_KEYWORDS.items():

        for keyword in keywords:

            if keyword in text:
                detected.append(intent)
                break

    return list(set(detected))


def classify_destination(url):
    """
    Determine what a destination URL appears to represent.
    """

    if not url:
        return []

    url = normalize(url)

    detected = []

    for destination_type, keywords in DESTINATION_KEYWORDS.items():

        for keyword in keywords:

            if keyword in url:
                detected.append(destination_type)
                break

    return list(set(detected))


def get_domain(url):
    """Extract hostname from URL."""

    if not url:
        return None

    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return None


def has_suspicious_redirect_parameters(url):
    """
    Look for URL parameters commonly associated with
    redirects.

    This is NOT proof of malicious behavior.
    It is simply a useful signal.
    """

    if not url:
        return False

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        redirect_parameters = {
            "url",
            "redirect",
            "redirect_url",
            "redirect_uri",
            "return",
            "return_url",
            "next",
            "continue",
            "target",
            "destination",
            "dest",
        }

        return any(
            parameter.lower() in redirect_parameters
            for parameter in params
        )

    except Exception:
        return False


def compare_intent_to_destination(text, destination):
    """
    Compare what the element says with what its destination
    appears to represent.
    """

    text_intents = classify_text(text)
    destination_types = classify_destination(destination)

    mismatches = []

    # Example:
    # "Download" -> /subscribe
    if "download" in text_intents:

        if "subscription" in destination_types:
            mismatches.append(
                "download_action_leads_to_subscription"
            )

        if "payment" in destination_types:
            mismatches.append(
                "download_action_leads_to_payment"
            )

        if "login" in destination_types:
            mismatches.append(
                "download_action_leads_to_login"
            )

    # "Close" shouldn't normally lead to payment/subscription.
    if "close" in text_intents:

        if "subscription" in destination_types:
            mismatches.append(
                "close_action_leads_to_subscription"
            )

        if "payment" in destination_types:
            mismatches.append(
                "close_action_leads_to_payment"
            )

        if "login" in destination_types:
            mismatches.append(
                "close_action_leads_to_login"
            )

    # "Continue" is ambiguous, so we don't automatically
    # classify it as malicious.
    if "continue" in text_intents:

        if "payment" in destination_types:
            mismatches.append(
                "continue_action_leads_to_payment"
            )

    return mismatches


def calculate_risk(signals):
    """
    Convert evidence into a simple risk level.

    This is intentionally transparent and rule-based.
    """

    score = 0

    for signal in signals:

        if signal in {
            "download_action_leads_to_subscription",
            "download_action_leads_to_payment",
            "close_action_leads_to_subscription",
            "close_action_leads_to_payment",
        }:
            score += 50

        elif signal in {
            "download_action_leads_to_login",
            "close_action_leads_to_login",
            "continue_action_leads_to_payment",
        }:
            score += 30

        elif signal == "cross_domain_destination":
            score += 20

        elif signal == "redirect_parameter":
            score += 15

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def analyze_link(link, page_url):
    """
    Analyze a single link.
    """

    text = link.get("text", "")
    destination = link.get("href", "")

    signals = []

    page_domain = get_domain(page_url)
    destination_domain = get_domain(destination)

    # Check for cross-domain navigation.
    if (
        page_domain
        and destination_domain
        and page_domain != destination_domain
    ):
        signals.append("cross_domain_destination")

    # Check for redirect-style parameters.
    if has_suspicious_redirect_parameters(destination):
        signals.append("redirect_parameter")

    # Compare visible intent with destination.
    signals.extend(
        compare_intent_to_destination(
            text,
            destination
        )
    )

    score, level = calculate_risk(signals)

    return {
        "element_type": "link",
        "text": text,
        "destination": destination,
        "risk_score": score,
        "risk_level": level,
        "signals": signals,
    }


def analyze_button(button, page_url):
    """
    Analyze a button.

    Buttons often don't have a direct href, so we primarily
    inspect their JavaScript/form destination information.
    """

    text = button.get("text", "")

    destination = (
        button.get("formaction")
        or button.get("href")
        or ""
    )

    signals = []

    if destination:

        page_domain = get_domain(page_url)
        destination_domain = get_domain(destination)

        if (
            page_domain
            and destination_domain
            and page_domain != destination_domain
        ):
            signals.append("cross_domain_destination")

        if has_suspicious_redirect_parameters(destination):
            signals.append("redirect_parameter")

        signals.extend(
            compare_intent_to_destination(
                text,
                destination
            )
        )

    score, level = calculate_risk(signals)

    return {
        "element_type": "button",
        "text": text,
        "destination": destination,
        "onclick": button.get("onclick"),
        "risk_score": score,
        "risk_level": level,
        "signals": signals,
    }


def analyze_scan(scan_result):
    """
    Analyze the complete scanner output.
    """

    page = scan_result.get("page", {})

    page_url = page.get(
        "final_url",
        page.get("requested_url", "")
    )

    findings = []

    for link in scan_result.get("links", []):

        result = analyze_link(
            link,
            page_url
        )

        # Keep all findings for now.
        findings.append(result)

    for button in scan_result.get("buttons", []):

        result = analyze_button(
            button,
            page_url
        )

        findings.append(result)

    # Highest-risk finding first.
    findings.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    return {
        "page": page,
        "findings": findings,
    }


def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python redirect_detector.py <scan.json>"
        )
        sys.exit(1)

    filename = sys.argv[1]

    try:

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

            scan_result = json.load(file)

        analysis = analyze_scan(scan_result)

        # Save the analysis to analysis.json
        with open(
            "analysis.json",
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                analysis,
                file,
                indent=2,
                ensure_ascii=False
            )

        print("Analysis completed successfully.")
        print("Output saved to: analysis.json")

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

