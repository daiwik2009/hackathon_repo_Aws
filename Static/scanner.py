import sys
import json
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "AI-Bodyguard/0.1 "
    "(Security Research Scanner)"
)


def fetch_page(url):
    """Download a webpage and return its HTML."""

    headers = {
        "User-Agent": USER_AGENT
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=15,
        allow_redirects=True
    )

    response.raise_for_status()

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "html": response.text,
    }


def clean_text(text):
    """Normalize whitespace."""

    if not text:
        return ""

    return " ".join(text.split())


def scan_links(soup, base_url):
    """Extract hyperlinks."""

    links = []

    for tag in soup.find_all("a"):
        href = tag.get("href")

        if not href:
            continue

        links.append({
            "text": clean_text(tag.get_text(" ", strip=True)),
            "href": urljoin(base_url, href),
            "target": tag.get("target"),
            "rel": tag.get("rel"),
        })

    return links


def scan_buttons(soup, base_url):
    """Extract buttons and button-like elements."""

    buttons = []

    # Real <button> elements
    for tag in soup.find_all("button"):
        buttons.append({
            "type": "button",
            "text": clean_text(tag.get_text(" ", strip=True)),
            "name": tag.get("name"),
            "value": tag.get("value"),
            "onclick": tag.get("onclick"),
            "formaction": tag.get("formaction"),
        })

    # <input type="button"> etc.
    for tag in soup.find_all("input"):
        input_type = (tag.get("type") or "").lower()

        if input_type in {
            "button",
            "submit",
            "reset",
            "image"
        }:
            buttons.append({
                "type": f"input:{input_type}",
                "text": tag.get("value", ""),
                "name": tag.get("name"),
                "value": tag.get("value"),
                "onclick": tag.get("onclick"),
                "formaction": tag.get("formaction"),
            })

    # Elements made clickable with JavaScript
    for tag in soup.find_all(attrs={"role": "button"}):
        buttons.append({
            "type": "role-button",
            "text": clean_text(tag.get_text(" ", strip=True)),
            "onclick": tag.get("onclick"),
        })

    return buttons


def scan_forms(soup, base_url):
    """Extract forms and their controls."""

    forms = []

    for form in soup.find_all("form"):

        action = form.get("action") or base_url

        form_data = {
            "action": urljoin(base_url, action),
            "method": (form.get("method") or "GET").upper(),
            "name": form.get("name"),
            "id": form.get("id"),
            "inputs": []
        }

        for input_tag in form.find_all(["input", "textarea", "select"]):

            control = {
                "tag": input_tag.name,
                "type": input_tag.get("type"),
                "name": input_tag.get("name"),
                "value": input_tag.get("value"),
                "placeholder": input_tag.get("placeholder"),
            }

            form_data["inputs"].append(control)

        forms.append(form_data)

    return forms


def scan_js_handlers(soup):
    """Find inline JavaScript event handlers."""

    handlers = []

    event_attributes = [
        "onclick",
        "ondblclick",
        "onmousedown",
        "onmouseup",
        "onmouseover",
        "onkeydown",
        "onkeyup",
        "onsubmit",
        "onchange",
        "onload",
    ]

    for tag in soup.find_all(True):

        for event in event_attributes:

            value = tag.get(event)

            if value:
                handlers.append({
                    "tag": tag.name,
                    "event": event,
                    "code": value,
                    "text": clean_text(
                        tag.get_text(" ", strip=True)
                    )[:200]
                })

    return handlers


def scan_scripts(soup):
    """Find external and inline JavaScript."""

    scripts = []

    for script in soup.find_all("script"):

        src = script.get("src")

        if src:
            scripts.append({
                "type": "external",
                "src": src
            })
        else:
            code = script.get_text()

            if code.strip():
                scripts.append({
                    "type": "inline",
                    "length": len(code),
                    "preview": code[:500]
                })

    return scripts


def scan_page(url):
    """Run the complete page scanner."""

    page = fetch_page(url)

    soup = BeautifulSoup(
        page["html"],
        "html.parser"
    )

    result = {
        "page": {
            "requested_url": page["requested_url"],
            "final_url": page["final_url"],
            "status_code": page["status_code"],
            "content_type": page["content_type"],
            "title": clean_text(
                soup.title.get_text()
            ) if soup.title else None,
        },

        "links": scan_links(
            soup,
            page["final_url"]
        ),

        "buttons": scan_buttons(
            soup,
            page["final_url"]
        ),

        "forms": scan_forms(
            soup,
            page["final_url"]
        ),

        "javascript_handlers": scan_js_handlers(
            soup
        ),

        "scripts": scan_scripts(
            soup
        )
    }

    return result


def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python scanner.py <URL>"
        )
        sys.exit(1)

    url = sys.argv[1]

    try:
        result = scan_page(url)

        # Save scanner output for detector.py
        with open("scan.json", "w", encoding="utf-8") as file:
            json.dump(
                result,
                file,
                indent=2,
                ensure_ascii=False
            )

        # Also print it to terminal
        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False
            )
        )

        print("\nScan saved to scan.json")

    except requests.RequestException as error:
        print(f"Request failed: {error}")
        sys.exit(1)

    except Exception as error:
        print(f"Scanner error: {error}")
        sys.exit(1)




if __name__ == "__main__":
    main()