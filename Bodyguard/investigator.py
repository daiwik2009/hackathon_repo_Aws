"""
AI Bodyguard Investigator

Responsible for deeper investigation of URLs discovered
during static/dynamic webpage analysis.

Pipeline:

URL
 ├── Static scanner
 │      ↓
 │   Detector
 │
 └── Dynamic scanner
        ↓
     Detector
        ↓
   AI Analyser
        ↓
   needs investigation?
        ↓
   recursively investigate discovered URL
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from Static import scan_page
from Dynamic import scan

from .detector import analyze_scan
from .ai_analyser import analyse


MAX_DEPTH = 3


class Investigator:

    def __init__(self, max_depth: int = MAX_DEPTH):
        self.max_depth = max_depth
        self.visited = set()

    # ============================================================
    # URL HELPERS
    # ============================================================

    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Normalize a URL enough to prevent duplicate investigations.
        """

        if not url:
            return ""

        parsed = urlparse(url)

        # Remove fragment because:
        # example.com/page#one
        # and
        # example.com/page#two
        # are the same network resource.
        return parsed._replace(fragment="").geturl()

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Only allow normal HTTP/HTTPS URLs to be investigated.
        """

        if not url:
            return False

        try:
            parsed = urlparse(url)

            return parsed.scheme in {
                "http",
                "https"
            } and bool(parsed.netloc)

        except Exception:
            return False

    # ============================================================
    # DISCOVER URLS FROM SCANNER OUTPUT
    # ============================================================

    @staticmethod
    def extract_discovered_urls(scan_result: dict) -> set[str]:
        """
        Extract URLs that were actually discovered by the scanner.

        These URLs become candidates for deeper investigation.

        The AI must NOT be allowed to invent arbitrary URLs.
        """

        discovered = set()

        page = scan_result.get("page", {})

        # --------------------------------------------------------
        # Page URLs
        # --------------------------------------------------------

        for key in (
            "requested_url",
            "final_url"
        ):
            value = page.get(key)

            if value:
                discovered.add(value)

        base_url = (
            page.get("final_url")
            or page.get("requested_url")
            or ""
        )

        # --------------------------------------------------------
        # Links
        # --------------------------------------------------------

        for link in scan_result.get("links", []):

            href = link.get("href")

            if href:
                discovered.add(
                    urljoin(base_url, href)
                )

        # --------------------------------------------------------
        # Buttons
        # --------------------------------------------------------

        for button in scan_result.get("buttons", []):

            destination = (
                button.get("href")
                or button.get("formaction")
            )

            if destination:
                discovered.add(
                    urljoin(base_url, destination)
                )

        # --------------------------------------------------------
        # Forms
        # --------------------------------------------------------

        for form in scan_result.get("forms", []):

            action = form.get("action")

            if action:
                discovered.add(
                    urljoin(base_url, action)
                )

        # --------------------------------------------------------
        # Clean them
        # --------------------------------------------------------

        cleaned = set()

        for url in discovered:

            normalized = Investigator.normalize_url(url)

            if Investigator.is_valid_url(normalized):
                cleaned.add(normalized)

        return cleaned

    # ============================================================
    # SINGLE INVESTIGATION
    # ============================================================

    def investigate(
        self,
        url: str,
        depth: int = 0
    ) -> dict:

        url = self.normalize_url(url)

        # --------------------------------------------------------
        # Validate URL
        # --------------------------------------------------------

        if not self.is_valid_url(url):

            return {
                "url": url,
                "status": "invalid_url"
            }

        # --------------------------------------------------------
        # Prevent loops
        # --------------------------------------------------------

        if url in self.visited:

            return {
                "url": url,
                "status": "already_scanned"
            }

        # --------------------------------------------------------
        # Prevent infinite recursion
        # --------------------------------------------------------

        if depth > self.max_depth:

            return {
                "url": url,
                "status": "depth_limit_reached"
            }

        self.visited.add(url)

        print(
            f"[INVESTIGATOR] "
            f"Scanning depth {depth}: {url}"
        )

        # ========================================================
        # STATIC SCAN
        # ========================================================

        try:

            static_result = scan_page(url)

            static_analysis = analyze_scan(
                static_result
            )

        except Exception as error:

            static_result = {
                "error": str(error)
            }

            static_analysis = {
                "page": {},
                "findings": [],
                "error": str(error)
            }

        # ========================================================
        # DYNAMIC SCAN
        # ========================================================

        try:

            dynamic_result = scan(url)

            dynamic_analysis = analyze_scan(
                dynamic_result
            )

        except Exception as error:

            dynamic_result = {
                "error": str(error)
            }

            dynamic_analysis = {
                "page": {},
                "findings": [],
                "error": str(error)
            }

        # ========================================================
        # DISCOVER POSSIBLE NEXT DESTINATIONS
        # ========================================================

        discovered_urls = set()

        if isinstance(static_result, dict):

            discovered_urls.update(
                self.extract_discovered_urls(
                    static_result
                )
            )

        if isinstance(dynamic_result, dict):

            discovered_urls.update(
                self.extract_discovered_urls(
                    dynamic_result
                )
            )

        # The original URL itself isn't interesting
        # as a child investigation.
        discovered_urls.discard(url)

        # ========================================================
        # BUILD AI EVIDENCE
        # ========================================================

        evidence = {

            "url": url,

            "depth": depth,

            "static": {
                "scan": static_result,
                "analysis": static_analysis
            },

            "dynamic": {
                "scan": dynamic_result,
                "analysis": dynamic_analysis
            },

            "discovered_urls": sorted(
                discovered_urls
            )
        }

        # ========================================================
        # AI ANALYSIS
        # ========================================================

        try:

            judgement = analyse(
                evidence
            )

        except Exception as error:

            return {
                "url": url,
                "depth": depth,
                "status": "ai_analysis_failed",
                "error": str(error),
                "evidence": evidence
            }

        # ========================================================
        # CURRENT RESULT
        # ========================================================

        result = {

            "url": url,

            "depth": depth,

            "judgement": judgement,

            "investigations": []
        }

        # ========================================================
        # DEEPER INVESTIGATION
        # ========================================================

        if (
            judgement.get(
                "needs_more_investigation",
                False
            )
            and depth < self.max_depth
        ):

            requests = judgement.get(
                "investigation",
                []
            )

            for request in requests:

                target = request.get("url")

                if not target:
                    continue

                target = self.normalize_url(
                    target
                )

                # ------------------------------------------------
                # SECURITY CHECK:
                # AI can only investigate URLs that our scanners
                # actually discovered.
                # ------------------------------------------------

                if target not in discovered_urls:

                    print(
                        "[INVESTIGATOR] "
                        f"Rejected AI-requested URL: {target}"
                    )

                    continue

                if target in self.visited:
                    continue

                print(
                    "[INVESTIGATOR] "
                    f"Deeper investigation requested: {target}"
                )

                child_result = self.investigate(
                    target,
                    depth + 1
                )

                result[
                    "investigations"
                ].append(
                    {
                        "reason": request.get(
                            "reason",
                            ""
                        ),
                        "result": child_result
                    }
                )

        return result


# ================================================================
# SIMPLE CLI
# ================================================================

if __name__ == "__main__":

    import json
    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python -m Bodyguard.investigator <URL>"
        )

        raise SystemExit(1)

    target = sys.argv[1]

    investigator = Investigator()

    final_result = investigator.investigate(
        target
    )

    print(
        json.dumps(
            final_result,
            indent=2,
            ensure_ascii=False
        )
    )