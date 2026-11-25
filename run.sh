#!/bin/bash
# My gitignored convenience script to invoke git-permalink-fixer from anywhere
#
# Example:
# cd ~/paramoundev/instadebit-core
# ~/git/git-permalink-fixer/run.sh -n -v --repo-alias rails-instadebit-core --repo-alias risk-instadebit-core --output-json-report git_permalink_checker.json --line-shift-tolerance

GITHUB_TOKEN="$(secret-from-first "github.com/hle-pc/personal_access_token.chrome-ext-notifier")" || return 1
export GITHUB_TOKEN

(cd ~/git/git-permalink-fixer && uv run git-permalink-fixer "$@")
