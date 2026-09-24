"""
AI Bodyguard detector.

Responsibility:
    Detect suspicious signals from scanner output.

Input:
    scan_result dictionary produced by scanner.py

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
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# INTENT KEYWORDS
# ---------------------------------------------------------------------------

INTENT_KEYWORDS = {
    "download": [
        "download",
        "get file",
        "save file",
        "save",
        "export",
        "pdf",
        "document",
        "attachment",
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


# ---------------------------------------------------------------------------
# DESTINATION KEYWORDS
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# NORMALIZATION
# ---------------------------------------------------------------------------

def normalize(text: str | None) -> str:
    """Normalize text for keyword comparison."""

    if not text:
        return ""

    return " ".join(str(text).lower().split())


# ---------------------------------------------------------------------------
# TEXT CLASSIFICATION
# ---------------------------------------------------------------------------

def classify_text(text: str | None) -> list[str]:
    """
    Determine what action a visible element appears to represent.
    """

    text = normalize(text)

    detected = []

    for intent, keywords in INTENT_KEYWORDS.items():

        for keyword in keywords:

            if keyword in text:
                detected.append(intent)
                break

    return sorted(set(detected))


# ---------------------------------------------------------------------------
# DESTINATION CLASSIFICATION
# ---------------------------------------------------------------------------

def classify_destination(url: str | None) -> list[str]:
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

    return sorted(set(detected))


# ---------------------------------------------------------------------------
# DOMAIN
# ---------------------------------------------------------------------------

def get_domain(url: str | None) -> str | None:
    """Extract hostname from a URL."""

    if not url:
        return None

    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# REDIRECT PARAMETERS
# ---------------------------------------------------------------------------

def has_suspicious_redirect_parameters(url: str | None) -> bool:
    """
    Detect URL parameters commonly associated with redirects.

    This is only a signal.
    It does not prove malicious behaviour.
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


# ---------------------------------------------------------------------------
# INTENT → DESTINATION MISMATCH
# ---------------------------------------------------------------------------

def compare_intent_to_destination(
    text: str | None,
    destination: str | None,
) -> list[str]:
    """
    Compare what an element appears to promise with
    what its destination appears to do.
    """

    text_intents = classify_text(text)
    destination_types = classify_destination(destination)

    mismatches = []

    # -------------------------------------------------------
    # Download
    # -------------------------------------------------------

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

    # -------------------------------------------------------
    # Close / dismiss
    # -------------------------------------------------------

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

    # -------------------------------------------------------
    # Continue
    # -------------------------------------------------------

    if "continue" in text_intents:

        if "payment" in destination_types:
            mismatches.append(
                "continue_action_leads_to_payment"
            )

    return sorted(set(mismatches))


# ---------------------------------------------------------------------------
# LINK DETECTOR
# ---------------------------------------------------------------------------

def detect_link(link: dict, page_url: str) -> dict:
    """
    Detect suspicious signals in a scanned link.
    """

    text = link.get("text", "")
    destination = link.get("href", "")

    signals = []

    page_domain = get_domain(page_url)
    destination_domain = get_domain(destination)

    # -------------------------------------------------------
    # Cross-domain navigation
    # -------------------------------------------------------

    if (
        page_domain
        and destination_domain
        and page_domain != destination_domain
    ):
        signals.append(
            "cross_domain_destination"
        )

    # -------------------------------------------------------
    # Redirect parameter
    # -------------------------------------------------------

    if has_suspicious_redirect_parameters(destination):
        signals.append(
            "redirect_parameter"
        )

    # -------------------------------------------------------
    # Intent mismatch
    # -------------------------------------------------------

    signals.extend(
        compare_intent_to_destination(
            text,
            destination,
        )
    )

    signals = sorted(set(signals))

    return {
        "element_type": "link",
        "text": text,
        "destination": destination,
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# BUTTON DETECTOR
# ---------------------------------------------------------------------------

def detect_button(button: dict, page_url: str) -> dict:
    """
    Detect suspicious signals in a scanned button.

    Buttons may not have a direct URL, so we inspect:
        - formaction
        - href
        - onclick
    """

    text = button.get("text", "")

    destination = (
        button.get("formaction")
        or button.get("href")
        or ""
    )

    onclick = button.get("onclick") or ""

    signals = []

    # -------------------------------------------------------
    # Direct destination
    # -------------------------------------------------------

    if destination:

        page_domain = get_domain(page_url)
        destination_domain = get_domain(destination)

        if (
            page_domain
            and destination_domain
            and page_domain != destination_domain
        ):
            signals.append(
                "cross_domain_destination"
            )

        if has_suspicious_redirect_parameters(
            destination
        ):
            signals.append(
                "redirect_parameter"
            )

        signals.extend(
            compare_intent_to_destination(
                text,
                destination,
            )
        )

    # -------------------------------------------------------
    # Inline JavaScript
    #
    # We don't execute JavaScript.
    # We only inspect it for obvious URL/action clues.
    # -------------------------------------------------------

    if onclick:

        onclick_lower = normalize(onclick)

        # Obvious redirect/navigation indicators.
        javascript_navigation_keywords = [
            "window.location",
            "location.href",
            "location.assign",
            "location.replace",
            "window.open",
        ]

        if any(
            keyword in onclick_lower
            for keyword in javascript_navigation_keywords
        ):
            signals.append(
                "javascript_navigation"
            )

        # Inspect the JavaScript text itself for
        # destination intent.
        js_destination_types = classify_destination(
            onclick_lower
        )

        if "subscription" in js_destination_types:

            if "download" in classify_text(text):
                signals.append(
                    "download_action_leads_to_subscription"
                )

            if "close" in classify_text(text):
                signals.append(
                    "close_action_leads_to_subscription"
                )

        if "payment" in js_destination_types:

            if "download" in classify_text(text):
                signals.append(
                    "download_action_leads_to_payment"
                )

            if "close" in classify_text(text):
                signals.append(
                    "close_action_leads_to_payment"
                )

            if "continue" in classify_text(text):
                signals.append(
                    "continue_action_leads_to_payment"
                )

        if "login" in js_destination_types:

            if "download" in classify_text(text):
                signals.append(
                    "download_action_leads_to_login"
                )

            if "close" in classify_text(text):
                signals.append(
                    "close_action_leads_to_login"
                )

    signals = sorted(set(signals))

    return {
        "element_type": "button",
        "text": text,
        "destination": destination,
        "onclick": onclick,
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# FORM DETECTOR
# ---------------------------------------------------------------------------

def detect_form(form: dict, page_url: str) -> dict:
    """
    Detect suspicious signals in a form.

    Forms are included because the scanner already extracts them.
    """

    action = form.get("action", "")
    method = str(
        form.get("method", "GET")
    ).upper()

    signals = []

    page_domain = get_domain(page_url)
    destination_domain = get_domain(action)

    # -------------------------------------------------------
    # Cross-domain form submission
    # -------------------------------------------------------

    if (
        page_domain
        and destination_domain
        and page_domain != destination_domain
    ):
        signals.append(
            "cross_domain_destination"
        )

    # -------------------------------------------------------
    # Redirect parameters
    # -------------------------------------------------------

    if has_suspicious_redirect_parameters(action):
        signals.append(
            "redirect_parameter"
        )

    # -------------------------------------------------------
    # Identify sensitive-looking controls
    # -------------------------------------------------------

    input_names = []

    for control in form.get("inputs", []):

        name = normalize(
            control.get("name")
        )

        input_type = normalize(
            control.get("type")
        )

        placeholder = normalize(
            control.get("placeholder")
        )

        input_names.extend([
            name,
            input_type,
            placeholder,
        ])

    combined_input_text = " ".join(
        value
        for value in input_names
        if value
    )

    if any(
        keyword in combined_input_text
        for keyword in [
            "password",
            "passwd",
        ]
    ):
        signals.append(
            "password_input"
        )

    if any(
        keyword in combined_input_text
        for keyword in [
            "card",
            "credit",
            "debit",
            "cvv",
            "cvc",
            "billing",
        ]
    ):
        signals.append(
            "payment_input"
        )

    return {
        "element_type": "form",
        "text": "",
        "destination": action,
        "method": method,
        "signals": sorted(set(signals)),
    }


# ---------------------------------------------------------------------------
# COMPLETE SCAN ANALYSIS
# ---------------------------------------------------------------------------

def analyze_scan(scan_result: dict) -> dict:
    """
    Analyze the complete scanner output.

    IMPORTANT:
        This function detects evidence only.

        It does NOT assign:
            - risk score
            - risk level
            - ALLOW
            - WARN
            - BLOCK

        Those decisions belong to analyser.py.
    """

    page = scan_result.get(
        "page",
        {}
    )

    page_url = (
        page.get("final_url")
        or page.get("requested_url")
        or ""
    )

    findings = []

    # -------------------------------------------------------
    # LINKS
    # -------------------------------------------------------

    for link in scan_result.get(
        "links",
        []
    ):

        findings.append(
            detect_link(
                link,
                page_url,
            )
        )

    # -------------------------------------------------------
    # BUTTONS
    # -------------------------------------------------------

    for button in scan_result.get(
        "buttons",
        []
    ):

        findings.append(
            detect_button(
                button,
                page_url,
            )
        )

    # -------------------------------------------------------
    # FORMS
    # -------------------------------------------------------

    for form in scan_result.get(
        "forms",
        []
    ):

        findings.append(
            detect_form(
                form,
                page_url,
            )
        )

    return {
        "page": page,

        "findings": findings,
    }


# ---------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# ---------------------------------------------------------------------------

def main() -> None:

    if len(sys.argv) != 2:

        print(
            "Usage: python detector.py <scan.json>"
        )

        sys.exit(1)

    filename = sys.argv[1]

    try:

        # ---------------------------------------------------
        # READ SCANNER OUTPUT
        # ---------------------------------------------------

        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as file:

            scan_result = json.load(file)

        # ---------------------------------------------------
        # DETECT SIGNALS
        # ---------------------------------------------------

        analysis = analyze_scan(
            scan_result
        )

        # ---------------------------------------------------
        # WRITE ANALYSIS
        # ---------------------------------------------------

        with open(
            "analysis.json",
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                analysis,
                file,
                indent=2,
                ensure_ascii=False,
            )

        # ---------------------------------------------------
        # DISPLAY
        # ---------------------------------------------------

        print(
            json.dumps(
                analysis,
                indent=2,
                ensure_ascii=False,
            )
        )

        print(
            "\nAnalysis saved to: analysis.json"
        )

    except FileNotFoundError:

        print(
            f"File not found: {filename}"
        )

        sys.exit(1)

    except json.JSONDecodeError:

        print(
            f"Invalid JSON file: {filename}"
        )

        sys.exit(1)

    except Exception as error:

        print(
            f"Detector error: {error}"
        )

        sys.exit(1)


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
