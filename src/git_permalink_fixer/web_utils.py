import base64
import binascii
import json
import os
import sys
import webbrowser
from typing import List, Optional

import requests

from git_permalink_fixer.url_utils import parse_github_blob_permalink


def _get_github_token() -> Optional[str]:
    """
    Retrieves GitHub token from GITHUB_TOKEN env var or prompts user.
    Returns token string or None if not found/provided or if stdin is not a TTY.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        print("ℹ️ Using GITHUB_TOKEN from environment variable.", file=sys.stderr)
        return token

    if not sys.stdin.isatty():
        print("⚠️ Cannot prompt for GitHub token: stdin is not a TTY. Skipping API fallback.", file=sys.stderr)
        return None

    try:
        token_input = input(
            "\n🔑 Enter GitHub Personal Access Token (PAT) for API access (or press Enter to skip): "
        ).strip()
        if token_input:
            return token_input
        print("No GitHub token provided by user. Skipping API fallback.", file=sys.stderr)
        return None
    except EOFError:
        print("⚠️ Cannot prompt for GitHub token: EOF while reading input. Skipping API fallback.", file=sys.stderr)
        return None
    # Allow KeyboardInterrupt to propagate if user cancels.


def _fetch_github_content_with_api(owner: str, repo: str, ref: str, path: str, token: str) -> Optional[List[str]]:
    """Helper to fetch content using GitHub API, trying raw then JSON endpoint."""
    api_url_base = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {"Authorization": f"token {token}"}
    params = {"ref": ref}

    headers_json = headers.copy()
    headers_json["Accept"] = "application/vnd.github.v3+json"
    try:
        print(f"ℹ️ API Fallback: Attempting to fetch JSON metadata from API for {path}...", file=sys.stderr)
        response_json = requests.get(api_url_base, headers=headers_json, params=params, timeout=15)
        response_json.raise_for_status()
        data = response_json.json()

        if isinstance(data, list) or data.get("type") != "file":
            print(
                f"❌ API Fallback: Path {path} is not a file (type: {data.get('type', 'directory' if isinstance(data, list) else 'unknown')}).",
                file=sys.stderr,
            )
            return None
        if "content" in data and data.get("encoding") == "base64":
            decoded_content = base64.b64decode(data["content"]).decode("utf-8")
            if not decoded_content:
                print(f"⚠️ API Fallback: Decoded content for {path} is empty.", file=sys.stderr)
                return None

            # Save decoded content to a temporary file
            # This is not necessary for the return value, but can be useful for debugging.
            with open("temp_decoded_content.txt", "w", encoding="utf-8") as temp_file:
                temp_file.write(decoded_content)

            return decoded_content.splitlines()
        if "download_url" in data and data["download_url"]:
            response_download = requests.get(
                data["download_url"], headers=headers, timeout=20
            )  # Use token for download_url
            response_download.raise_for_status()
            if not response_download.text:
                print(f"⚠️ API Fallback: Downloaded content for {path} is empty.", file=sys.stderr)
                return None
            return response_download.text.splitlines()
        print(f"❌ API Fallback: No usable content or download_url in JSON for {path}.", file=sys.stderr)
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError, binascii.Error, UnicodeDecodeError) as e_api:
        print(f"❌ API Fallback (JSON/download): Error processing for {path}: {e_api}", file=sys.stderr)
        return None


def fetch_raw_github_content_from_url(github_file_url: str) -> Optional[List[str]]:
    """Fetches raw content from a GitHub file URL, with API fallback for 4xx errors."""
    parsed_details = parse_github_blob_permalink(github_file_url)
    if not parsed_details:
        print(f"Error: Could not parse GitHub URL for raw content: {github_file_url}", file=sys.stderr)
        return None
    owner, repo, ref, path, _, _ = parsed_details
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    try:
        print(f"ℹ️ Attempting to fetch raw content from {raw_url}...", file=sys.stderr)
        response = requests.get(raw_url, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)
        return response.text.splitlines()
    except requests.exceptions.HTTPError as e_http:
        if 400 <= e_http.response.status_code < 500:  # Client error (4xx)
            print(
                f"⚠️ Client error ({e_http.response.status_code}) fetching from {raw_url}. Status: {e_http.response.reason}. Attempting API fallback...",
                file=sys.stderr,
            )
            token = _get_github_token()
            if token:
                return _fetch_github_content_with_api(owner, repo, ref, path, token)
            print(
                f"❌ Failed to fetch from {raw_url} (status {e_http.response.status_code}) and no token for API fallback.",
                file=sys.stderr,
            )
            return None
        # Server error (5xx) or other HTTPError not in 4xx range
        print(
            f"❌ HTTP error {e_http.response.status_code} fetching raw content from {raw_url}: {e_http.response.reason}",
            file=sys.stderr,
        )
        return None
    except requests.exceptions.RequestException as e:  # Catch other initial request errors
        print(f"❌ Network error fetching raw content from {raw_url}: {e}", file=sys.stderr)
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
        except webbrowser.Error as e:  # webbrowser.Error is the base class for errors from this module
            print(f"⚠️ Could not open URL '{url}' in browser: {e}. Please open manually.")
