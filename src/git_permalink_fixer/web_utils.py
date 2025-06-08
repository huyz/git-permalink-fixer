from typing import List, Optional
import sys
import webbrowser

import requests

from git_permalink_fixer.url_utils import parse_any_github_url_for_raw_content



def fetch_raw_github_content_from_url(github_file_url: str) -> Optional[List[str]]:
    """Fetches raw content from a GitHub file URL."""
    parsed_details = parse_any_github_url_for_raw_content(github_file_url)
    if not parsed_details:
        print(f"Error: Could not parse GitHub URL for raw content: {github_file_url}", file=sys.stderr)
        return None
    owner, repo, ref, path = parsed_details
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    try:
        response = requests.get(raw_url, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching raw content from {raw_url}: {e}", file=sys.stderr)
        return None


def open_urls_in_browser(urls_with_descriptions: List[tuple[str, str]]) -> None:
    """
    Attempts to open a list of URLs in a web browser, each with a description.

    Args:
        urls_with_descriptions: A list of tuples, where each tuple is (description, url).
    """
    if not urls_with_descriptions:
        return

    for description, url in urls_with_descriptions:
        print(f"🌐 Attempting to open {description}: {url}")
        try:
            webbrowser.open(url)
        except webbrowser.Error as e: # webbrowser.Error is the base class for errors from this module
            print(f"⚠️ Could not open URL '{url}' in browser: {e}. Please open manually.")
