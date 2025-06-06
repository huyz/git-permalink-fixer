import webbrowser
from typing import List


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
