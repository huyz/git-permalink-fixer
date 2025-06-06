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
    r"https://github\.com/([^/]+)/([^/]+)/(?:blob|tree)/([a-f0-9]{7,40})(?:/([^#\s\?]+))?(?:#L(\d+)(?:-L(\d+))?)?",
    re.IGNORECASE,
)

