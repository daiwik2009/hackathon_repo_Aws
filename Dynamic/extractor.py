import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup


def clean_text(text):
    """Normalize whitespace."""
    if not text:
        return ""
    return " ".join(text.split())


def extract_links(soup, base_url):
    """Extract hyperlinks."""
    links = []

    for tag in soup.find_all("a"):
        href = tag.get("href")

        if not href:
            continue

        rel_val = tag.get("rel")
        if isinstance(rel_val, list):
            rel_val = " ".join(rel_val)

        links.append({
            "text": clean_text(tag.get_text(" ", strip=True)),
            "href": urljoin(base_url, href),
            "target": tag.get("target"),
            "rel": rel_val,
        })

    return links


def extract_buttons(soup):
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

        if input_type in {"button", "submit", "reset", "image"}:
            buttons.append({
                "type": f"input:{input_type}",
                "text": tag.get("value", ""),
                "name": tag.get("name"),
                "value": tag.get("value"),
                "onclick": tag.get("onclick"),
                "formaction": tag.get("formaction"),
            })

    # Elements using role="button" (excluding actual <button> or <input> tags to avoid duplicates)
    for tag in soup.find_all(attrs={"role": "button"}):
        if tag.name in {"button", "input"}:
            continue
        buttons.append({
            "type": "role-button",
            "text": clean_text(tag.get_text(" ", strip=True)),
            "onclick": tag.get("onclick"),
        })

    return buttons


def extract_forms(soup, base_url):
    """Extract forms and their controls."""
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        target_action = action if action else base_url

        form_data = {
            "action": urljoin(base_url, target_action),
            "method": (form.get("method") or "GET").upper(),
            "name": form.get("name"),
            "id": form.get("id"),
            "inputs": [],
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


def extract_js_handlers(soup):
    """Extract inline JavaScript event handlers."""
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
                    "text": clean_text(tag.get_text(" ", strip=True))[:200],
                })

    return handlers


def extract_scripts(soup):
    """Extract external and inline JavaScript."""
    scripts = []

    for script in soup.find_all("script"):
        src = script.get("src")

        if src:
            scripts.append({
                "type": "external",
                "src": src,
            })
        else:
            code = script.get_text()
            if code.strip():
                scripts.append({
                    "type": "inline",
                    "length": len(code),
                    "preview": code[:500],
                })

    return scripts


def extract_page(html_file="temp.html", metadata_file="metadata.json"):
    """Extract Bodyguard-compatible evidence."""
    # Load rendered HTML
    with open(html_file, "r", encoding="utf-8") as file:
        html = file.read()

    # Load browser metadata
    with open(metadata_file, "r", encoding="utf-8") as file:
        metadata = json.load(file)

    soup = BeautifulSoup(html, "html.parser")

    requested_url = metadata.get("requested_url")
    final_url = metadata.get("final_url") or requested_url

    result = {
        "page": {
            "requested_url": requested_url,
            "final_url": final_url,
            "status_code": metadata.get("status_code"),
            "content_type": metadata.get("content_type"),
            "title": (
                clean_text(soup.title.get_text()) if soup.title else None
            ),
        },
        "links": extract_links(soup, final_url),
        "buttons": extract_buttons(soup),
        "forms": extract_forms(soup, final_url),
        "javascript_handlers": extract_js_handlers(soup),
        "scripts": extract_scripts(soup),
    }

    return result


def save_result(result, output_file="scan.json"):
    """Save Bodyguard-compatible JSON."""
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    result = extract_page()
    save_result(result)
    print(json.dumps(result, indent=2, ensure_ascii=False))