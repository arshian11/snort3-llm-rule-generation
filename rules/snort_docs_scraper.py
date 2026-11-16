
import requests
import time
import re
import os

from bs4 import BeautifulSoup
from markdownify import markdownify as md
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from urllib.robotparser import RobotFileParser

# ============================================================
# CONFIGURATION
# ============================================================

BASE_URL = "https://docs.snort.org/rules/"
OUTPUT_FILE = "snort3_complete_rule_documentation.txt"

HEADERS = {
    "User-Agent": "SnortDocumentationResearchBot/1.0"
}

REQUEST_DELAY = 0.5
TIMEOUT = 30

# Restrict crawling to the Snort rules documentation.
ALLOWED_DOMAIN = "docs.snort.org"
ALLOWED_PATH = "/rules/"

# ============================================================
# SESSION
# ============================================================

session = requests.Session()
session.headers.update(HEADERS)

visited = set()
failed = set()
pages = []

# ============================================================
# ROBOTS.TXT CHECK
# ============================================================

# robots_url = "https://docs.snort.org/robots.txt"

# robots = RobotFileParser()
# robots.set_url(robots_url)

# try:
#     robots.read()
# except Exception:
#     print("Could not retrieve robots.txt.")
#     print("Verify the site's crawling policy before proceeding.")

# ============================================================
# ROBOTS.TXT CHECK
# ============================================================

robots_url = "https://docs.snort.org/robots.txt"

robots = RobotFileParser()
ROBOTS_ACCESS_ALLOWED = False

try:
    response = session.get(
        robots_url,
        timeout=TIMEOUT
    )

    print(f"Robots status: {response.status_code}")

    if response.status_code == 404:
        # No robots.txt file exists.
        # Do not interpret the HTML error page as a policy.
        ROBOTS_ACCESS_ALLOWED = True
        print("No robots.txt found. Proceeding.")

    elif response.status_code == 200:
        robots.parse(response.text.splitlines())

        ROBOTS_ACCESS_ALLOWED = robots.can_fetch(
            HEADERS["User-Agent"],
            BASE_URL
        )

        print("Robots policy loaded.")

    else:
        print("Unable to establish crawling permission.")
        ROBOTS_ACCESS_ALLOWED = False

except requests.RequestException as error:
    print(f"Robots request failed: {error}")
    ROBOTS_ACCESS_ALLOWED = False

print("Crawling permitted:", ROBOTS_ACCESS_ALLOWED)

# ============================================================
# URL NORMALIZATION
# ============================================================

# def normalize_url(url):

#     url = urldefrag(url)[0]

#     parsed = urlparse(url)

#     if parsed.scheme not in ("http", "https"):
#         return None

#     if parsed.netloc.lower() != ALLOWED_DOMAIN:
#         return None

#     if not parsed.path.startswith(ALLOWED_PATH):
#         return None

#     # Ignore non-documentation files.
#     if re.search(
#         r"\.(pdf|png|jpg|jpeg|svg|gif|css|js|zip|xml|json)$",
#         parsed.path,
#         re.IGNORECASE
#     ):
#         return None

#     # Remove unnecessary trailing slash variations.
#     path = parsed.path.rstrip("/") or "/"

#     return f"https://{ALLOWED_DOMAIN}{path}"


def normalize_url(url):

    url = urldefrag(url)[0]

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return None

    if parsed.netloc.lower() != ALLOWED_DOMAIN:
        return None

    # Accept both /rules and /rules/
    if not (
        parsed.path == "/rules"
        or parsed.path.startswith("/rules/")
    ):
        return None

    # Ignore non-documentation files.
    if re.search(
        r"\.(pdf|png|jpg|jpeg|svg|gif|css|js|zip|xml|json)$",
        parsed.path,
        re.IGNORECASE
    ):
        return None

    # Preserve trailing slash for the root documentation page.
    path = parsed.path

    if path == "/rules":
        path = "/rules/"

    return f"https://{ALLOWED_DOMAIN}{path}"


# ============================================================
# EXTRACT MAIN DOCUMENTATION CONTENT
# ============================================================

def extract_content(soup):

    # Try common documentation content containers.
    main = (
        soup.select_one("main")
        or soup.select_one("article")
        or soup.select_one(".content")
        or soup.body
    )

    if main is None:
        return ""

    # Remove navigation and irrelevant elements.
    for element in main.select(
        "nav, header, footer, aside, "
        "script, style, noscript, "
        ".sidebar, .navbar, .breadcrumbs, "
        ".pagination, .edit-page"
    ):
        element.decompose()

    # Convert HTML to Markdown-like clean text.
    content = md(
        str(main),
        heading_style="ATX",
        bullets="-",
        code_language="",
        strip=["img", "button"]
    )

    # Clean whitespace.
    content = content.replace("\xa0", " ")
    content = re.sub(r"[ \t]+\n", "\n", content)
    content = re.sub(r"\n{3,}", "\n\n", content)

    return content.strip()


# ============================================================
# DISCOVER INTERNAL LINKS
# ============================================================

def discover_links(soup, current_url):

    discovered = set()

    for anchor in soup.find_all("a", href=True):

        absolute_url = urljoin(
            current_url,
            anchor["href"]
        )

        clean_url = normalize_url(absolute_url)

        if clean_url and clean_url not in visited:
            discovered.add(clean_url)

    return discovered


# ============================================================
# FETCH A DOCUMENTATION PAGE
# ============================================================

# def fetch_page(url):

#     try:

#         if not robots.can_fetch(HEADERS["User-Agent"], url):
#             print(f"[ROBOTS BLOCKED] {url}")
#             return None, None

#         response = session.get(
#             url,
#             timeout=TIMEOUT
#         )

#         response.raise_for_status()

#         # Only process HTML pages.
#         if "text/html" not in response.headers.get(
#             "Content-Type", ""
#         ).lower():
#             return None, None

#         soup = BeautifulSoup(
#             response.text,
#             "html.parser"
#         )

#         return soup, response.url

#     except requests.RequestException as error:

#         print(f"[FAILED] {url}")
#         print(f"         {error}")

#         failed.add(url)

#         return None, None


def fetch_page(url):

    try:

        print(f"       Fetching: {url}")

        response = session.get(
            url,
            timeout=TIMEOUT
        )

        print(f"       HTTP Status: {response.status_code}")

        response.raise_for_status()

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "text/html" not in content_type:
            print("       Skipping: Not HTML")
            return None, None

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        return soup, response.url

    except requests.RequestException as error:

        print(f"[FAILED] {url}")
        print(f"         {error}")

        failed.add(url)

        return None, None


# ============================================================
# RECURSIVE CRAWLER
# ============================================================

def crawl(start_url):

    queue = deque([start_url])

    print("Initial queue:", list(queue))

    while queue:

        url = queue.popleft()

        url = normalize_url(url)

        if not url or url in visited:
            continue

        visited.add(url)

        print(
            f"[{len(visited):03d}] Crawling: {url}"
        )

        soup, final_url = fetch_page(url)

        if soup is None:
            continue

        content = extract_content(soup)

        if content:

            title = soup.title.get_text(
                strip=True
            ) if soup.title else url

            pages.append({
                "url": final_url,
                "title": title,
                "content": content
            })

            print(f"       Extracted: {title}")

        # Discover links from the entire page,
        # including nested sidebar sections.
        links = discover_links(soup, final_url)

        for link in sorted(links):

            if link not in visited:
                queue.append(link)

        time.sleep(REQUEST_DELAY)


# ============================================================
# SAVE EVERYTHING TO TXT
# ============================================================

def save_documentation():

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "=" * 80 + "\n"
        )

        file.write(
            "SNORT 3 - COMPLETE RULE WRITING DOCUMENTATION\n"
        )

        file.write(
            "Source: https://docs.snort.org/rules/\n"
        )

        file.write(
            f"Total pages extracted: {len(pages)}\n"
        )

        file.write(
            "=" * 80 + "\n\n"
        )

        for index, page in enumerate(pages, 1):

            file.write("\n")
            file.write("#" * 80 + "\n")

            file.write(
                f"PAGE {index}: {page['title']}\n"
            )

            file.write(
                f"URL: {page['url']}\n"
            )

            file.write("#" * 80 + "\n\n")

            file.write(page["content"])

            file.write("\n\n")

    print("\n========================================")
    print("SCRAPING COMPLETED")
    print("========================================")

    print(f"Pages extracted : {len(pages)}")
    print(f"Failed pages    : {len(failed)}")
    print(f"Output file     : {os.path.abspath(OUTPUT_FILE)}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_url = normalize_url(BASE_URL)

    print("Starting Snort documentation crawler...")
    print(f"Starting URL: {start_url}\n")

    crawl(start_url)

    save_documentation()

    if failed:
        print("\nFailed URLs:")

        for url in sorted(failed):
            print(url)
