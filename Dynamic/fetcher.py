import json
import os

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from url_safety import is_safe_url


NAVIGATION_TIMEOUT_MS = 20_000
MAX_HTML_BYTES = 5 * 1024 * 1024  # 5 MB


def _guard_route(route):
    """
    FIX: previously nothing validated where the *browser itself* went.
    A page.goto() to a public-looking URL that 302-redirects to an
    internal address, or a page that embeds <img src="http://internal/">
    or fires a fetch() at an internal service, would all sail through
    unchecked -- SSRF isn't limited to the top-level navigation.
    Intercepting every request the page makes and checking it here
    covers redirects, sub-resources, and script-initiated fetches in
    one place.
    """

    request_url = route.request.url

    safe, _reason = is_safe_url(request_url)

    if safe:
        route.continue_()
    else:
        route.abort()


def fetch(url, workdir="."):
    """
    Fetch `url` with a real browser and write the rendered HTML +
    metadata into `workdir`.

    FIX: `workdir` used to not exist -- fetch()/prettify()/extract_page()
    all read and wrote fixed filenames ("temp.html", "metadata.json") in
    the current directory. That's a shared-mutable-state bug: two scans
    running at the same time (two concurrent /scan requests, or a WARN
    page's AI review overlapping with a fresh request) would stomp on
    each other's files mid-scan. Each call now gets its own directory
    (see Dynamic/__init__.py, which creates a fresh tempdir per call).
    """

    safe, reason = is_safe_url(url)
    if not safe:
        raise ValueError(f"Refusing to fetch unsafe URL ({reason}): {url}")

    browser = None

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)

            # FIX: accept_downloads=False stops a malicious page from
            # triggering a file download that could hang page.goto() or
            # write attacker-controlled files to disk.
            context = browser.new_context(accept_downloads=False)
            page = context.new_page()

            page.route("**/*", _guard_route)

            page.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
            page.set_default_timeout(NAVIGATION_TIMEOUT_MS)

            try:
                response = page.goto(url, wait_until="networkidle")
            except PlaywrightTimeoutError:
                # FIX: many real pages never reach "networkidle" (ads,
                # analytics beacons, polling, websockets) and would
                # previously just hang until Playwright's timeout fired
                # and fail the whole scan. Falling back to
                # "domcontentloaded" still gets us a usable DOM instead
                # of losing the scan entirely.
                response = page.goto(url, wait_until="domcontentloaded")

            html = page.content()

            # FIX: capture everything we need from `page`/`response`
            # *before* the finally block closes the browser -- these
            # objects aren't usable once the connection is torn down.
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

        finally:
            # FIX: previously nothing closed the browser if page.goto()
            # raised -- every failed fetch leaked a Chromium process.
            if browser is not None:
                browser.close()

    if len(result["html"].encode("utf-8", errors="ignore")) > MAX_HTML_BYTES:
        result["html"] = result["html"][:MAX_HTML_BYTES]

    os.makedirs(workdir, exist_ok=True)

    # Save HTML separately
    with open(os.path.join(workdir, "temp.html"), "w", encoding="utf-8") as f:
        f.write(result["html"])

    # Remove HTML from metadata
    del result["html"]

    # Save metadata
    with open(os.path.join(workdir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)