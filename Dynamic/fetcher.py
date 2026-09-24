from playwright.sync_api import sync_playwright
import json

def fetch(u):
    def fetch_page(url):

        with sync_playwright() as p:

            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            response = page.goto(
                url,
                wait_until="networkidle"
            )

            html = page.content()

            result = {
                "requested_url": url,
                "final_url": page.url,
                "status_code": response.status if response else None,
                "content_type": (
                    response.headers.get("content-type")
                    if response
                    else None
                ),
                "html": html,
            }

            browser.close()

            return result


    result = fetch_page(u)


    # Save HTML separately
    with open("temp.html", "w", encoding="utf-8") as f:
        f.write(result["html"])


    # Remove HTML from metadata
    del result["html"]


    # Save metadata
    with open("metadata.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)



