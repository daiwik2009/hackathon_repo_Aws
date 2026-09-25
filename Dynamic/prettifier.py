import os

from bs4 import BeautifulSoup


def prettify(workdir="."):
    path = os.path.join(workdir, "temp.html")

    with open(path, "r", encoding="utf-8") as f:
        html = f.read()

    soup = BeautifulSoup(html, "html.parser")

    pretty_html = soup.prettify()

    with open(path, "w", encoding="utf-8") as f:
        f.write(pretty_html)