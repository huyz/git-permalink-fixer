import re

# File extensions (of text files) to search in a repo
# TIP: `git ls-files | grep -o "\.\w\+" | sort -u`
COMMON_TEXT_FILE_EXTENSIONS = {
    ".bash",
    ".bat",
    ".c",
    ".conf",
    ".config",
    ".cpp",
    ".d2",
    ".go",
    ".h",
    ".htm",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".json",
    ".md",
    ".mdx",
    ".php",
    ".properties",
    ".property",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".rst",
    ".sh",
    ".sql",
    ".svg",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}

COMMON_EXTENSIONLESS_REPO_FILES = {
    "README",
    "LICENSE",
    "CHANGELOG",
    "CONTRIBUTING",
    "AUTHORS",
    "INSTALL",
    "Makefile",
    "Dockerfile",
    ".gitignore",
    ".env",
    ".envrc",
}

GITHUB_REMOTE_RE = re.compile(r"^(?:git@|https?://)github\.com[:/]")

GITHUB_PERMALINK_RE = re.compile(
    # Matches: https://github.com/owner/repo/blob/ref/path/to/file.ext#L10-L20
    # ref can be a commit hash, branch name, or tag name.
    r"https://github\.com/([^/]+)/([^/]+)/(blob|tree)/([^/]+)(?:/([^#?\s]+))?(?:\?[^#\s]+)?(?:#L(\d+)(?:-L(\d+))?)?",
    re.IGNORECASE,
)

# General pattern to find GitHub URLs in text content.
# Used by re.findall, so it's a string, not a compiled regex object here.
# Note that this regex is stricter than what is normally allowed in a URL; e.g.
# we exclude parentheses and more.
GITHUB_URL_FIND_PATTERN = r"https://github\.com/[^][()<>\"'{}|\\^`\s]+"
