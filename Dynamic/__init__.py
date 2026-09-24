from .fetcher import fetch
from .prettifier import prettify
from .extractor import extract_page


def scan(url):
    """
    Run the complete dynamic webpage scanner.
    """

    fetch(url)


    prettify()


    result = extract_page()

    return result

#Dynamic init