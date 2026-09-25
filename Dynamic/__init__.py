import shutil
import tempfile

from .fetcher import fetch
from .extractor import extract_page


def scan(url):
    """
    Run the complete dynamic webpage scanner.

    FIX: previously fetch()/prettify()/extract_page() all read and
    wrote fixed filenames ("temp.html", "metadata.json") in the
    current working directory. That's shared mutable state: two
    concurrent calls to scan() (e.g. two overlapping /scan requests)
    would corrupt each other's files mid-scan. Each call now gets its
    own throwaway directory, used for exactly one scan, then removed.

    FIX: dropped the prettify() step. extract_page() parses temp.html
    with BeautifulSoup itself regardless of whether it was
    pretty-printed first, so prettifying was a full extra parse+
    re-serialize pass that changed nothing about what gets extracted.
    If you want the saved temp.html to be human-readable for manual
    debugging, call Dynamic.prettifier.prettify(workdir) yourself on
    the side -- it no longer runs on the hot path.
    """

    workdir = tempfile.mkdtemp(prefix="bodyguard_dynamic_")

    try:
        fetch(url, workdir)
        result = extract_page(workdir)
        return result
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


#Dynamic init