#!/usr/bin/env bash
# S-0.15 / REQ-A-03: datazoo-oauth2 must contain zero provider-specific code.
#
# Red: grep -riE 'microsoft|entra|sap|datasphere|google|drive|azure|dataverse' src/
#      returns hits.
# Green: zero hits.
#
# Usage: scripts/check_no_vendor_names.sh
# Exit code 0 = clean (no vendor names found). Exit code 1 = violation found.
#
# Scope: this checks *compiled code* (identifiers, string literals emitted at
# runtime, control flow) -- the actual REQ-A-03 design boundary ("a hit is a
# design failure"). It intentionally strips `//` comments before matching,
# because several files carry deliberate provenance comments explaining what
# was extracted from where (e.g. "generalised from erpl-web's
# MicrosoftEntraTokenManager") -- that is honest migration documentation,
# not a vendor coupling, and forcing it out of the source would make the
# history harder to follow for no behavioural benefit. See
# docs/EXTRACTION_NOTES.md for the full discussion, including the one
# genuine near-miss this check caught during extraction (a "SAP Datasphere"
# string literal in OAuth2FlowV2's console instructions, since generalised)
# and the one *not* fixed because fixing it would change behaviour depended
# on by erpl-web's own tests (OAuth2Config::GetClientType()'s SAP BTP
# client-id heuristics -- see EXTRACTION_NOTES.md).
#
# Limitation: comment-stripping is a simple `//...` removal, not a full C++
# tokenizer, so a `//` inside a string literal would also be stripped. No
# such literal exists in this codebase today (verified by hand at S-0.15
# time); if one is ever added, re-verify this script still catches it.
#
# Notes on deliberate near-misses that are NOT violations:
#  - "duckdb_httplib_openssl", "duckdb.hpp", "DuckDbSecrets", etc. contain
#    "duckdb", not "drive"/"google"/etc. -- not matched by the pattern below.
#  - Comments in docs/EXTRACTION_NOTES.md and this script itself legitimately
#    discuss the vendor names being excluded; only src/ is scanned.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"

PATTERN='microsoft|entra|\bsap\b|datasphere|google|drive|azure|dataverse'

if [ ! -d "$SRC_DIR" ]; then
    echo "check_no_vendor_names: src/ directory not found at $SRC_DIR" >&2
    exit 1
fi

violations=""
while IFS= read -r -d '' file; do
    # Strip `//` line comments (and any leading whitespace before them),
    # then search what's left -- i.e. actual code and string literals.
    code_only="$(sed -E 's#([[:space:]]|^)//.*$##' "$file")"
    hit="$(printf '%s\n' "$code_only" | grep -inE "$PATTERN" || true)"
    if [ -n "$hit" ]; then
        violations="${violations}${file}:
${hit}
"
    fi
done < <(find "$SRC_DIR" -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0)

if [ -n "$violations" ]; then
    echo "check_no_vendor_names: FAILED -- vendor-specific code found in src/:" >&2
    echo "$violations" >&2
    echo "datazoo-oauth2 must stay provider-agnostic (REQ-A-03). Move any" >&2
    echo "provider-specific logic into the consuming extension instead." >&2
    exit 1
fi

echo "check_no_vendor_names: OK -- no vendor-specific code found in src/ (comments excluded)"
exit 0
