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
 └── Dynamic scanner (only when heuristics.should_use_dynamic says so)
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

import logging
from urllib.parse import urljoin, urlparse

from Static import scan_page
from Dynamic import scan

from .detector import analyze_scan
from .ai_analyser import analyse
from .heuristics import should_use_dynamic
from url_safety import is_safe_url  # shared, project-root module

logger = logging.getLogger(__name__)

MAX_DEPTH = 3

# FIX: depth alone doesn't bound the work. A single page can contain
# dozens of discovered URLs, and the AI can request several of them for
# investigation at once -- each one triggers a full static (+ maybe
# dynamic) scan and its own OpenAI call. Without a total ceiling, one
# /scan request could fan out into dozens of expensive child
# investigations even while staying within MAX_DEPTH. This caps the
# whole investigation tree, not just how deep it can go.
MAX_TOTAL_INVESTIGATIONS = 25


class Investigator:

    def __init__(
        self,
        max_depth: int = MAX_DEPTH,
        max_total_investigations: int = MAX_TOTAL_INVESTIGATIONS,
    ):
        self.max_depth = max_depth
        self.max_total_investigations = max_total_investigations
        self.visited: set[str] = set()
        self.investigation_count = 0

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
        Only allow normal HTTP/HTTPS URLs that also pass the shared
        SSRF guard to be investigated.

        FIX: this previously only checked scheme + netloc, which is a
        syntax check, not a safety check. A URL like
        "http://169.254.169.254/latest/meta-data/" or
        "http://127.0.0.1:6379/" passed it fine. Every URL the
        Investigator is about to fetch -- especially recursively
        discovered ones an attacker-controlled page can plant --
        now goes through url_safety.is_safe_url() as well.
        """

        if not url:
            return False

        try:
            parsed = urlparse(url)

            if not (
                parsed.scheme in {"http", "https"}
                and bool(parsed.netloc)
            ):
                return False

        except Exception:
            return False

        safe, reason = is_safe_url(url)

        if not safe:
            logger.warning(
                "Rejected unsafe URL %s (%s)", url, reason
            )
            return False

        return True

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
        depth: int = 0,
        precomputed_static: dict | None = None,
        precomputed_dynamic: dict | None = None,
    ) -> dict:
        """
        Parameters
        ----------
        precomputed_static / precomputed_dynamic:
            Optional. When app.py has already scanned the *root* URL
            before deciding a WARN result deserves AI review, it can
            pass those results in here at depth 0 so this doesn't
            silently re-run the same static/dynamic scan a second
            time. Never used below depth 0 -- recursive child URLs are
            always scanned fresh here.
        """

        url = self.normalize_url(url)

        # --------------------------------------------------------
        # Validate URL (syntax + SSRF safety)
        # --------------------------------------------------------

        if not self.is_valid_url(url):

            return {
                "url": url,
                "status": "invalid_or_unsafe_url"
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

        # --------------------------------------------------------
        # Prevent excessive fan-out across the whole tree
        # --------------------------------------------------------

        if self.investigation_count >= self.max_total_investigations:

            return {
                "url": url,
                "status": "investigation_budget_exhausted"
            }

        self.visited.add(url)
        self.investigation_count += 1

        logger.info("Investigating depth %s: %s", depth, url)

        # ========================================================
        # STATIC SCAN
        # ========================================================

        if depth == 0 and precomputed_static is not None:
            static_result = precomputed_static
        else:
            try:
                static_result = scan_page(url)
            except Exception as error:
                static_result = {"error": str(error)}

        try:
            static_analysis = analyze_scan(static_result)
        except Exception as error:
            static_analysis = {
                "page": {},
                "findings": [],
                "error": str(error)
            }

        # ========================================================
        # DYNAMIC SCAN (only when the static result suggests it's
        # actually needed -- same heuristic app.py uses, so a
        # recursively investigated child URL doesn't unconditionally
        # pay for a Chromium launch it doesn't need)
        # ========================================================

        dynamic_result: dict = {}
        dynamic_analysis: dict = {"page": {}, "findings": []}

        if depth == 0 and precomputed_dynamic is not None:
            dynamic_result = precomputed_dynamic
            try:
                dynamic_analysis = analyze_scan(dynamic_result)
            except Exception as error:
                dynamic_analysis = {
                    "page": {}, "findings": [], "error": str(error)
                }

        elif isinstance(static_result, dict) and should_use_dynamic(static_result):
            try:
                dynamic_result = scan(url)
                dynamic_analysis = analyze_scan(dynamic_result)
            except Exception as error:
                dynamic_result = {"error": str(error)}
                dynamic_analysis = {
                    "page": {}, "findings": [], "error": str(error)
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

            logger.warning(
                "AI analysis failed for %s: %s", url, error
            )

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
            and self.investigation_count < self.max_total_investigations
        ):

            requests = judgement.get(
                "investigation",
                []
            )

            for request in requests:

                if self.investigation_count >= self.max_total_investigations:
                    logger.info(
                        "Investigation budget exhausted, stopping fan-out from %s",
                        url,
                    )
                    break

                target = request.get("url")

                if not target:
                    continue

                target = self.normalize_url(
                    target
                )

                # ------------------------------------------------
                # SECURITY CHECK:
                # AI can only investigate URLs that our scanners
                # actually discovered (extract_discovered_urls()
                # already ran every entry through the SSRF guard,
                # so this membership check also enforces safety).
                # ------------------------------------------------

                if target not in discovered_urls:

                    logger.warning(
                        "Rejected AI-requested URL not in discovered_urls: %s",
                        target,
                    )

                    continue

                if target in self.visited:
                    continue

                logger.info(
                    "Deeper investigation requested: %s", target
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

    logging.basicConfig(level=logging.INFO)

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