#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# scripts/setup-hooks.sh - one-time setup: points git at the tracked
# hooks in .githooks/ instead of the untracked (and gitignored-by-default)
# .git/hooks/ directory.
#
# Run once after cloning:
#   scripts/setup-hooks.sh
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

git -C "$REPO_ROOT" config core.hooksPath .githooks
chmod +x "$REPO_ROOT"/.githooks/pre-commit "$REPO_ROOT"/.githooks/pre-push
chmod +x "$REPO_ROOT"/tests/*.sh

echo "Git hooks installed (core.hooksPath -> .githooks)."
echo "  pre-commit: lints staged files (cppcheck/shellcheck/gcc -fsyntax-only)"
echo "  pre-push:   runs the full test suite (tests/run_all.sh) when a push"
echo "              touches av/ or userspace/avctl/ - needs root, via pkexec"
echo
echo "Bypass either once with --no-verify if you really need to (not"
echo "recommended, especially right before tagging a release)."
