"""
AI Bodyguard detector.

Responsibility:
    Detect suspicious signals from scanner output.

Input:
    scan_result dictionary produced by Static or Dynamic scanner.

Output:
    analysis dictionary containing:
        - page
        - findings

The detector identifies evidence/signals.
Final risk scoring and ALLOW/WARN/BLOCK decisions
are handled by analyser.py.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import parse_qs, urljoin, urlparse


# ============================================================
# INTENT KEYWORDS
# ============================================================

INTENT_KEYWORDS = {
    "download": [
        "download",
        "get file",
        "save file",
        "export",
        "attachment",
        "document",
        "pdf",
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


# ============================================================
# DESTINATION KEYWORDS
# ============================================================

DESTINATION_KEYWORDS = {
    "subscription": [
        "subscribe",
        "subscription",
        "membership",
        "pricing",
        "plan",
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


# ============================================================
# NORMALIZATION
# ============================================================

def normalize(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(str(text).lower().split())


# ============================================================
# TEXT CLASSIFICATION
# ============================================================

def classify_text(text: str | None) -> list[str]:
    text = normalize(text)
    detected = [
        intent
        for intent, keywords in INTENT_KEYWORDS.items()
        if any(keyword in text for keyword in keywords)
    ]
    return sorted(set(detected))


# ============================================================
# DESTINATION CLASSIFICATION
# ============================================================

def classify_destination(url: str | None) -> list[str]:
    if not url:
        return []

    url = normalize(url)
    detected = [
        destination_type
        for destination_type, keywords in DESTINATION_KEYWORDS.items()
        if any(keyword in url for keyword in keywords)
    ]
    return sorted(set(detected))


# ============================================================
# DOMAIN
# ============================================================

def get_domain(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return None


# ============================================================
# REDIRECT PARAMETERS
# ============================================================

def has_suspicious_redirect_parameters(url: str | None) -> bool:
    if not url:
        return False

    try:
        parsed = urlparse(url)
        parameters = parse_qs(parsed.query)

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
            param.lower() in redirect_parameters for param in parameters
        )
    except Exception:
        return False


# ============================================================
# INTENT → DESTINATION MISMATCH
# ============================================================

def compare_intent_to_destination(
    text: str | None,
    destination: str | None,
) -> list[str]:
    text_intents = classify_text(text)
    destination_types = classify_destination(destination)

    mismatches = []

    if "download" in text_intents:
        if "subscription" in destination_types:
            mismatches.append("download_action_leads_to_subscription")
        if "payment" in destination_types:
            mismatches.append("download_action_leads_to_payment")
        if "login" in destination_types:
            mismatches.append("download_action_leads_to_login")

    if "close" in text_intents:
        if "subscription" in destination_types:
            mismatches.append("close_action_leads_to_subscription")
        if "payment" in destination_types:
            mismatches.append("close_action_leads_to_payment")
        if "login" in destination_types:
            mismatches.append("close_action_leads_to_login")

    if "continue" in text_intents and "payment" in destination_types:
        mismatches.append("continue_action_leads_to_payment")

    return sorted(set(mismatches))


# ============================================================
# LINK DETECTOR
# ============================================================

def detect_link(link: dict, page_url: str) -> dict:
    text = link.get("text", "")
    destination = urljoin(page_url, link.get("href", ""))

    signals = []

    page_domain = get_domain(page_url)
    destination_domain = get_domain(destination)

    if page_domain and destination_domain and page_domain != destination_domain:
        signals.append("cross_domain_destination")

    if has_suspicious_redirect_parameters(destination):
        signals.append("redirect_parameter")

    signals.extend(compare_intent_to_destination(text, destination))

    return {
        "element_type": "link",
        "text": text,
        "destination": destination,
        "signals": sorted(set(signals)),
    }


# ============================================================
# BUTTON DETECTOR
# ============================================================

def detect_button(button: dict, page_url: str) -> dict:
    text = button.get("text", "")
    raw_dest = button.get("formaction") or button.get("href") or ""
    destination = urljoin(page_url, raw_dest) if raw_dest else ""
    onclick = button.get("onclick") or ""

    signals = []

    if destination:
        page_domain = get_domain(page_url)
        destination_domain = get_domain(destination)

        if page_domain and destination_domain and page_domain != destination_domain:
            signals.append("cross_domain_destination")

        if has_suspicious_redirect_parameters(destination):
            signals.append("redirect_parameter")

        signals.extend(compare_intent_to_destination(text, destination))

    if onclick:
        onclick_lower = normalize(onclick)
        navigation_keywords = [
            "window.location",
            "location.href",
            "location.assign",
            "location.replace",
            "window.open",
        ]

        if any(keyword in onclick_lower for keyword in navigation_keywords):
            signals.append("javascript_navigation")

        js_destination_types = classify_destination(onclick_lower)
        text_intents = classify_text(text)

        if "download" in text_intents:
            if "subscription" in js_destination_types:
                signals.append("download_action_leads_to_subscription")
            if "payment" in js_destination_types:
                signals.append("download_action_leads_to_payment")
            if "login" in js_destination_types:
                signals.append("download_action_leads_to_login")

    return {
        "element_type": "button",
        "text": text,
        "destination": destination,
        "onclick": onclick,
        "signals": sorted(set(signals)),
    }


# ============================================================
# FORM DETECTOR
# ============================================================

def detect_form(form: dict, page_url: str) -> dict:
    action = urljoin(page_url, form.get("action", ""))
    method = str(form.get("method", "GET")).upper()

    signals = []

    page_domain = get_domain(page_url)
    destination_domain = get_domain(action)

    if page_domain and destination_domain and page_domain != destination_domain:
        signals.append("cross_domain_destination")

    if has_suspicious_redirect_parameters(action):
        signals.append("redirect_parameter")

    input_names = []
    for control in form.get("inputs", []):
        input_names.extend([
            normalize(control.get("name")),
            normalize(control.get("type")),
            normalize(control.get("placeholder")),
        ])

    combined_input_text = " ".join(val for val in input_names if val)

    if any(keyword in combined_input_text for keyword in ["password", "passwd"]):
        signals.append("password_input")

    if any(
        keyword in combined_input_text
        for keyword in ["card", "credit", "debit", "cvv", "cvc", "billing"]
    ):
        signals.append("payment_input")

    return {
        "element_type": "form",
        "text": "",
        "destination": action,
        "method": method,
        "signals": sorted(set(signals)),
    }


# ============================================================
# COMPLETE SCAN ANALYSIS
# ============================================================

def analyze_scan(scan_result: dict) -> dict:
    page = scan_result.get("page", {})
    page_url = page.get("final_url") or page.get("requested_url") or ""

    findings = []

    for link in scan_result.get("links", []):
        finding = detect_link(link, page_url)
        if finding["signals"]:
            findings.append(finding)

    for button in scan_result.get("buttons", []):
        finding = detect_button(button, page_url)
        if finding["signals"]:
            findings.append(finding)

    for form in scan_result.get("forms", []):
        finding = detect_form(form, page_url)
        if finding["signals"]:
            findings.append(finding)

    return {
        "page": page,
        "findings": findings,
    }


# ============================================================
# COMMAND LINE
# ============================================================

def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python detector.py <scan.json>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        with open(filename, "r", encoding="utf-8") as file:
            scan_result = json.load(file)

        analysis = analyze_scan(scan_result)

        with open("analysis.json", "w", encoding="utf-8") as file:
            json.dump(analysis, file, indent=2, ensure_ascii=False)

        print(json.dumps(analysis, indent=2, ensure_ascii=False))

    except FileNotFoundError:
        print(f"File not found: {filename}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Invalid JSON file: {filename}")
        sys.exit(1)
    except Exception as error:
        print(f"Detector error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()