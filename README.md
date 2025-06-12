# Git Permalink Fixer

[![PyPI version](https://badge.fury.io/py/git-permalink-fixer.svg)](https://badge.fury.io/py/git-permalink-fixer)
[![Build Status](https://github.com/huyz/git-permalink-fixer/actions/workflows/test.yml/badge.svg)](https://github.com/huyz/git-permalink-fixer/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`git-permalink-fixer` is a command-line tool that scans your project files for GitHub permalinks (referencing commit
SHAs) and helps you update them to more resilient references (e.g., permalinks referencing tags or the latest commit on
the main branch, that still contains the same content) or create tags to preserve the original commits.

## The Problem

GitHub permalinks using full commit SHAs are great for pointing to a specific version of code at a point in time.
However, as repositories evolve, commits can become unreachable if branches are rebased or never merged into main.

This tool helps you manage and update these permalinks proactively before GitHub garbage-collects these commits.

It finds GitHub commit permalinks in a repository, checks if commits are merged into `main` and, for
unmerged commits, tries to find the closest ancestor in `main` (and checks that any line references
still make sense).
For unmerged commits, it prompts the user to replace its permalinks to new ones pointing to the
ancestor; it also provides a fallback of tagging the commit to protect it.

Supports GitHub permalinks of the form:
- `https://github.com/org/project/blob/commit_hash/url_path#Lline_start-Lline_end`
- `https://github.com/org/project/tree/commit_hash`

## Features

- **Scan various text file types**: Finds GitHub permalinks in Markdown, code, text files, etc.
    skipping git-ignored files.
- **Intelligent suggestions**:
  - Identifies if the linked commit is an ancestor of your main branch.
  - Suggests updating to a permalink on the main branch if the content still matches.
  - Allows manually specifying arbitrary replacement URLs.
  - Alternatively, allows creating and pushing a Git tag at the original commit so that GitHub never garbage-collects it.
- **Content verification**: Checks if the content at the original permalink line(s) matches the content (within a
    configurable line-shift tolerance) at the suggested new location before proposing a replacement. Private
    repositories are supported.
- **Interactive mode**: Prompts for action on each found permalink (replace, tag, skip).
- **Batch operations**: Options to automate frequent operations.
- **Repository aliasing**: Useful if your project references upstreams or mirrors or your repository has been renamed.
- **Dry-run mode**: See what changes would be made without modifying files.
- **JSON report**: Outputs a JSON report of changes made (or in dry-run mode, would make)

## Installation

Requires Python 3.9 or later.

To install from [PyPI](https://pypi.org/project/git-permalink-fixer/):

```bash
pipx install git-permalink-fixer
```

## Usage

Navigate to your Git repository's root directory and run:

```bash
cd $REPO_ROOT
git-permalink-fixer [path]
```

### Options

- **`--repo-alias REPO_ALIASES`**
    Alternative repository names (e.g., `'old-repo-name'`, `'project-alias'`) that should be considered aliases for the current repository when parsing permalinks.
    This flag can be used multiple times to specify different aliases.

- **`--main-branch MAIN_BRANCH`**
    Specify the main branch name (default: `main`).

- **`--tag-prefix TAG_PREFIX`**
    Specify the tag prefix for preserving commits (default: `permalinks/ref`).

- **`--line-shift-tolerance LINE_SHIFT_TOLERANCE`**
    Max number of lines to shift up/down when searching for matching content in ancestor commits (default: `20`).
    Can be an absolute number (e.g., `20`) or a percentage of the target file's lines (e.g., `10%`).
    Set to `0` or `0%` to disable shifting.

- **`--fetch-mode {prompt,always,never}`**
    Behavior for fetching commits not found locally from `origin` remote (default: `prompt`).
    - `prompt`: Ask for each commit or group.
    - `always`: Automatically fetch all missing commits.
    - `never`: Never fetch missing commits.

- **`--auto-accept-replace`**
    Automatically accept suggested replacements if verification is successful (e.g., ancestor found and lines match within tolerance, or user manually resolved to a verifiable state).
    Bypasses the final action prompt for these cases.

- **`--auto-fallback {tag,skip}`**
    If a permalink cannot be successfully replaced (e.g., no ancestor, or line content verification fails and isn't resolved by user), automatically choose a fallback action:
    - `tag`: Tag the original commit
    - `skip`: Skip the permalink
    Bypasses the final action prompt for these fallback cases.

- **`--non-interactive`**
    Enable non-interactive mode. This is a shorthand for setting:
    - `--auto-accept-replace`
    - `--auto-fallback tag`
    - `--fetch-mode always`
    User will not be prompted for decisions.

- **`--output-json-report OUTPUT_JSON_REPORT`**
    File path to output a JSON report of actions (replacements and tags).

- **`-v`, `--verbose`**
    Enable verbose output for more detailed logging.

- **`--version`**
    Show program's version number and exit.

- **`-n`, `--dry-run`**
    Show what would be done without making any changes (tags, file modifications, or remote pushes).
    *Note: will still attempt to fetch commits if they are not found locally.*

- **`-I`, `--no-ignore`**
    Disable checking `.gitignore`. By default, files ignored by git are skipped.
    Set this flag to include them in the search (current behavior before this flag).

### Environment variables

If a replacement URL points to private repositories, this tool will try to verify that the content at the original
permalink line(s) matches the content at the suggested new location.
You can set the following environment variable to authenticate:

- **`GITHUB_TOKEN`**: Personal access token with `repo` scope for private repositories.

### Examples

For example, to generate a JSON report of suggested permalink replacements without making any changes:

```bash
cd $REPO_ROOT
git-permalink-fixer --dry-run --non-interactive --output-json-report $(date -I).permalinks-to-replace.json --line-shift-tolerance '10%'
```
