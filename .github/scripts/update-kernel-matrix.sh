#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# update-kernel-matrix.sh - fetches kernel.org's release list and rewrites
# .github/kernel-versions.json's "versions" array with:
#   - the 2 most recently released non-EOL "longterm" (LTS) branches
#   - the current "stable" release
#
# Deliberately writes a plain JSON data file, NOT build-matrix.yml itself.
# GitHub refuses to let the default GITHUB_TOKEN (or the app-installation
# token peter-evans/create-pull-request uses) push a change to anything
# under .github/workflows/, even with `permissions: contents: write`
# granted - that directory needs the separate `workflows` OAuth scope,
# which only a PAT can carry. The first version of this script edited
# build-matrix.yml directly and every run failed with exactly that
# "refusing to allow a GitHub App to ... update workflow" error.
# build-matrix.yml now reads this file at run time instead (a
# load-kernel-matrix job + fromJSON()), so this script only ever touches
# a non-workflow file and never needs a PAT.
#
# This deliberately does NOT hardcode branch numbers (6.12, 6.18, ...) -
# it re-derives "the current 2 active LTS branches" from kernel.org's own
# EOL flag every run, so it keeps working unchanged once those branches
# are eventually retired and different ones take their place. See
# https://www.kernel.org/releases.json for the source data and
# https://www.kernel.org/releases.html for what "longterm"/"stable" mean.
#
# Run from the repo root. Exits 0 with no changes if the file already
# matches kernel.org's current releases; exits non-zero on any fetch/
# parse failure so the calling workflow doesn't silently open a bad PR.
set -euo pipefail

DATA_FILE="${1:-.github/kernel-versions.json}"
RELEASES_URL="https://www.kernel.org/releases.json"

if [ ! -f "$DATA_FILE" ]; then
  echo "::error::$DATA_FILE not found" >&2
  exit 1
fi

releases_json="$(curl -fsSL "$RELEASES_URL")"

current_stable="$(
  echo "$releases_json" \
    | jq -r '[.releases[] | select(.moniker=="stable")] | .[0].version // empty'
)"

# kernel.org's releases.json already lists exactly one entry PER active
# branch (each the latest patch release for that branch) - so no need to
# dedupe by major.minor here, just filter to non-EOL longterm entries and
# take the 2 with the highest version. `sort -V` (version sort) handles
# X.Y.Z ordering correctly, unlike a plain lexicographic sort.
mapfile -t lts_versions < <(
  echo "$releases_json" \
    | jq -r '.releases[] | select(.moniker=="longterm" and .iseol==false) | .version' \
    | sort -V \
    | tail -n 2
)

if [ -z "$current_stable" ]; then
  echo "::error::could not find a moniker==\"stable\" entry in $RELEASES_URL" >&2
  exit 1
fi
if [ "${#lts_versions[@]}" -lt 2 ]; then
  echo "::error::expected 2 non-EOL longterm releases, found ${#lts_versions[@]} in $RELEASES_URL" >&2
  exit 1
fi

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

# Only the "versions" array is replaced - any other top-level key (e.g.
# "_comment") in the existing file passes through unchanged.
jq \
  --arg lts1 "${lts_versions[0]}" \
  --arg lts2 "${lts_versions[1]}" \
  --arg stable "$current_stable" \
  '.versions = [$lts1, $lts2, $stable]' \
  "$DATA_FILE" > "$tmp_file"

if diff -q "$DATA_FILE" "$tmp_file" > /dev/null; then
  echo "kernel_version list already up to date (LTS: ${lts_versions[0]}, ${lts_versions[1]}; stable: $current_stable)"
  echo "changed=false" >> "${GITHUB_OUTPUT:-/dev/null}"
else
  mv "$tmp_file" "$DATA_FILE"
  trap - EXIT
  echo "updated kernel_version list (LTS: ${lts_versions[0]}, ${lts_versions[1]}; stable: $current_stable)"
  echo "changed=true" >> "${GITHUB_OUTPUT:-/dev/null}"
fi
