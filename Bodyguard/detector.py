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

    "warning": [
        "warning",
        "alert",
        "security alert",
        "virus detected",
        "infected",
        "urgent",
    ],

    "update": [
        "update",
        "upgrade",
        "install",
    ],

    "verify": [
        "verify",
        "verification",
        "confirm",
    ],

    "free": [
        "free",
        "claim",
        "reward",
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
# URL SCHEME DETECTOR
# ============================================================

def detect_url_scheme(url: str | None) -> str | None:
    """
    Detect potentially dangerous URL schemes.

    These are signals only.
    analyser.py decides how serious they are.
    """

    if not url:
        return None

    lowered = normalize(url)

    if lowered.startswith("javascript:"):
        return "javascript_url"

    if lowered.startswith("data:"):
        return "data_url"

    if lowered.startswith("vbscript:"):
        return "vbscript_url"

    return None


# ============================================================
# REDIRECT PARAMETERS
# ============================================================

REDIRECT_PARAMETER_NAMES = {
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


def has_suspicious_redirect_parameters(url: str | None) -> bool:
    if not url:
        return False

    try:
        parsed = urlparse(url)
        parameters = parse_qs(parsed.query)

        return any(
            param.lower() in REDIRECT_PARAMETER_NAMES
            for param in parameters
        )

    except Exception:
        return False


def redirect_value_points_externally(
    url: str | None,
    page_domain: str | None,
) -> bool:
    """
    NEW: check not just whether a redirect-style parameter exists, but
    whether its *value* is itself an absolute URL pointing at a
    different domain -- which is the actual open-redirect risk.

    A parameter named "next" with a same-site relative value
    ("next=/dashboard") is completely normal application behaviour and
    was previously scored identically to "next=https://evil.example/",
    which is the real attack pattern. This distinguishes the two.
    """

    if not url or not page_domain:
        return False

    try:
        parsed = urlparse(url)
        parameters = parse_qs(parsed.query)

        for param, values in parameters.items():

            if param.lower() not in REDIRECT_PARAMETER_NAMES:
                continue

            for value in values:

                value_domain = get_domain(value)

                if value_domain and value_domain != page_domain:
                    return True

        return False

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

    # --------------------------------------------------------
    # DOWNLOAD
    # --------------------------------------------------------

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

        if "redirect" in destination_types:
            mismatches.append(
                "download_action_leads_to_redirect"
            )

    # --------------------------------------------------------
    # CLOSE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # CONTINUE
    # --------------------------------------------------------

    if "continue" in text_intents:

        if "payment" in destination_types:
            mismatches.append(
                "continue_action_leads_to_payment"
            )

        if "subscription" in destination_types:
            mismatches.append(
                "continue_action_leads_to_subscription"
            )

        if "login" in destination_types:
            mismatches.append(
                "continue_action_leads_to_login"
            )

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    if "verify" in text_intents:

        if "payment" in destination_types:
            mismatches.append(
                "verification_action_leads_to_payment"
            )

        if "subscription" in destination_types:
            mismatches.append(
                "verification_action_leads_to_subscription"
            )

    return sorted(set(mismatches))


# ============================================================
# LINK DETECTOR
# ============================================================

def detect_link(link: dict, page_url: str) -> dict:

    text = link.get("text", "")

    raw_href = link.get("href", "")
    destination = urljoin(page_url, raw_href)

    signals = []

    text_intents = classify_text(text)
    destination_types = classify_destination(destination)

    page_domain = get_domain(page_url)
    destination_domain = get_domain(destination)

    # --------------------------------------------------------
    # CROSS DOMAIN
    # --------------------------------------------------------

    cross_domain = (
        page_domain
        and destination_domain
        and page_domain != destination_domain
    )

    if cross_domain:
        signals.append("cross_domain_destination")

    # Stronger contextual signals

    if cross_domain:

        if "login" in text_intents:
            signals.append(
                "login_to_external_domain"
            )

        if "payment" in text_intents:
            signals.append(
                "payment_to_external_domain"
            )

        if "download" in text_intents:
            signals.append(
                "download_to_external_domain"
            )

    # --------------------------------------------------------
    # URL SCHEME
    # --------------------------------------------------------

    scheme_signal = detect_url_scheme(destination)

    if scheme_signal:
        signals.append(scheme_signal)

    # --------------------------------------------------------
    # REDIRECT PARAMETERS
    # --------------------------------------------------------

    if has_suspicious_redirect_parameters(destination):
        signals.append("redirect_parameter")

    if redirect_value_points_externally(destination, page_domain):
        signals.append("redirect_parameter_points_externally")

    # --------------------------------------------------------
    # INTENT MISMATCH
    # --------------------------------------------------------

    signals.extend(
        compare_intent_to_destination(
            text,
            destination
        )
    )

    return {
        "element_type": "link",
        "text": text,
        "destination": destination,
        "signals": sorted(set(signals)),
        "intent": text_intents,
        "destination_types": destination_types,
    }


# ============================================================
# BUTTON DETECTOR
# ============================================================

def detect_button(button: dict, page_url: str) -> dict:

    text = button.get("text", "")

    raw_dest = (
        button.get("formaction")
        or button.get("href")
        or ""
    )

    destination = (
        urljoin(page_url, raw_dest)
        if raw_dest
        else ""
    )

    onclick = button.get("onclick") or ""

    signals = []

    text_intents = classify_text(text)

    page_domain = get_domain(page_url)

    # --------------------------------------------------------
    # DESTINATION
    # --------------------------------------------------------

    if destination:

        destination_types = classify_destination(destination)

        destination_domain = get_domain(destination)

        cross_domain = (
            page_domain
            and destination_domain
            and page_domain != destination_domain
        )

        if cross_domain:
            signals.append(
                "cross_domain_destination"
            )

            if "login" in text_intents:
                signals.append(
                    "login_to_external_domain"
                )

            if "payment" in text_intents:
                signals.append(
                    "payment_to_external_domain"
                )

            if "download" in text_intents:
                signals.append(
                    "download_to_external_domain"
                )

        # URL scheme

        scheme_signal = detect_url_scheme(destination)

        if scheme_signal:
            signals.append(scheme_signal)

        # Redirect parameters

        if has_suspicious_redirect_parameters(destination):
            signals.append("redirect_parameter")

        if redirect_value_points_externally(destination, page_domain):
            signals.append("redirect_parameter_points_externally")

        # Intent mismatch

        signals.extend(
            compare_intent_to_destination(
                text,
                destination
            )
        )

    else:
        destination_types = []

    # --------------------------------------------------------
    # ONCLICK JAVASCRIPT
    # --------------------------------------------------------

    if onclick:

        onclick_lower = normalize(onclick)

        navigation_keywords = [
            "window.location",
            "location.href",
            "location.assign",
            "location.replace",
            "window.open",
            "document.location",
        ]

        if any(
            keyword in onclick_lower
            for keyword in navigation_keywords
        ):
            signals.append(
                "javascript_navigation"
            )

        # More generic dynamic navigation

        if "window.open" in onclick_lower:
            signals.append(
                "dynamic_navigation"
            )

        # Dynamic code execution signals

        if "eval(" in onclick_lower:
            signals.append(
                "dynamic_code_execution"
            )

        if "settimeout(" in onclick_lower:
            signals.append(
                "dynamic_javascript_execution"
            )

        if "setinterval(" in onclick_lower:
            signals.append(
                "dynamic_javascript_execution"
            )

        # Destination classification inside JS

        js_destination_types = classify_destination(
            onclick_lower
        )

        if "download" in text_intents:

            if "subscription" in js_destination_types:
                signals.append(
                    "download_action_leads_to_subscription"
                )

            if "payment" in js_destination_types:
                signals.append(
                    "download_action_leads_to_payment"
                )

            if "login" in js_destination_types:
                signals.append(
                    "download_action_leads_to_login"
                )

    return {
        "element_type": "button",
        "text": text,
        "destination": destination,
        "onclick": onclick,
        "signals": sorted(set(signals)),
        "intent": text_intents,
        "destination_types": destination_types,
    }


# ============================================================
# FORM DETECTOR
# ============================================================

def detect_form(form: dict, page_url: str) -> dict:

    action = urljoin(
        page_url,
        form.get("action", "")
    )

    method = str(
        form.get("method", "GET")
    ).upper()

    signals = []

    page_domain = get_domain(page_url)
    destination_domain = get_domain(action)

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    cross_domain = (
        page_domain
        and destination_domain
        and page_domain != destination_domain
    )

    if cross_domain:
        signals.append(
            "cross_domain_destination"
        )

    # --------------------------------------------------------
    # URL SCHEME
    # --------------------------------------------------------

    scheme_signal = detect_url_scheme(action)

    if scheme_signal:
        signals.append(scheme_signal)

    # --------------------------------------------------------
    # REDIRECT
    # --------------------------------------------------------

    if has_suspicious_redirect_parameters(action):
        signals.append("redirect_parameter")

    if redirect_value_points_externally(action, page_domain):
        signals.append("redirect_parameter_points_externally")

    # --------------------------------------------------------
    # INPUT ANALYSIS
    # --------------------------------------------------------

    input_names = []

    for control in form.get("inputs", []):

        input_names.extend([
            normalize(control.get("name")),
            normalize(control.get("type")),
            normalize(control.get("placeholder")),
        ])

    combined_input_text = " ".join(
        val
        for val in input_names
        if val
    )

    # --------------------------------------------------------
    # PASSWORD
    # --------------------------------------------------------

    password_input = any(
        keyword in combined_input_text
        for keyword in [
            "password",
            "passwd",
            "passcode",
        ]
    )

    if password_input:
        signals.append(
            "password_input"
        )

    # --------------------------------------------------------
    # EMAIL / USERNAME
    # --------------------------------------------------------

    email_input = any(
        keyword in combined_input_text
        for keyword in [
            "email",
            "e-mail",
            "username",
            "user_name",
            "userid",
        ]
    )

    if email_input:
        signals.append(
            "identity_input"
        )

    # --------------------------------------------------------
    # PAYMENT
    # --------------------------------------------------------

    payment_input = any(
        keyword in combined_input_text
        for keyword in [
            "card",
            "credit",
            "debit",
            "cvv",
            "cvc",
            "billing",
            "cardnumber",
            "card_number",
        ]
    )

    if payment_input:
        signals.append(
            "payment_input"
        )

    # --------------------------------------------------------
    # SENSITIVE DATA → EXTERNAL DOMAIN
    # --------------------------------------------------------

    if cross_domain and password_input:
        signals.append(
            "credential_submission_to_external_domain"
        )

    if cross_domain and payment_input:
        signals.append(
            "payment_submission_to_external_domain"
        )

    # --------------------------------------------------------
    # SENSITIVE DATA THROUGH GET
    # --------------------------------------------------------

    if method == "GET":

        if password_input:
            signals.append(
                "sensitive_data_via_get"
            )

        if payment_input:
            signals.append(
                "payment_data_via_get"
            )

    return {
        "element_type": "form",
        "text": "",
        "destination": action,
        "method": method,
        "signals": sorted(set(signals)),
        "inputs": input_names,
    }


# ============================================================
# COMPLETE SCAN ANALYSIS
# ============================================================

def analyze_scan(scan_result: dict) -> dict:

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

    # --------------------------------------------------------
    # LINKS
    # --------------------------------------------------------

    for link in scan_result.get(
        "links",
        []
    ):

        finding = detect_link(
            link,
            page_url
        )

        if finding["signals"]:
            findings.append(finding)

    # --------------------------------------------------------
    # BUTTONS
    # --------------------------------------------------------

    for button in scan_result.get(
        "buttons",
        []
    ):

        finding = detect_button(
            button,
            page_url
        )

        if finding["signals"]:
            findings.append(finding)

    # --------------------------------------------------------
    # FORMS
    # --------------------------------------------------------

    for form in scan_result.get(
        "forms",
        []
    ):

        finding = detect_form(
            form,
            page_url
        )

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

        print(
            "Usage: python detector.py <scan.json>"
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

        analysis = analyze_scan(
            scan_result
        )

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

        print(
            json.dumps(
                analysis,
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
            f"Invalid JSON file: {filename}"
        )

        sys.exit(1)

    except Exception as error:

        print(
            f"Detector error: {error}"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()