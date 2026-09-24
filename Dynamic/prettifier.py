from bs4 import BeautifulSoup

def prettify():
    with open("temp.html", "r", encoding="utf-8") as f:
        html = f.read()

    soup = BeautifulSoup(html, "html.parser")

    pretty_html = soup.prettify()

    with open("temp.html", "w", encoding="utf-8") as f:
        f.write(pretty_html)