"""Shared access to the archive: loading entries and the ordering everything uses.

Three generators read the same 100+ metadata.json files and need the same
answers about them — what order entries go in, what a class is called in prose,
where an entry lives on GitHub. That logic used to be copied per generator,
which meant a fix to one left the others reporting something different.
"""

import json
import os
import re
import sys
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_URL = "https://github.com/galletitaconpate/verified-exploits"

# Directories that hold tooling and inputs rather than entries.
SKIP_DIRS = ("tools", "data")

# Directory names are terse for filesystem reasons; spell them out for readers.
CLASS_LABELS = {
    "RCE": "RCE",
    "LPE": "LPE",
    "PrivEsc": "Priv Esc",
    "AuthBypass": "Auth Bypass",
    "PathTraversal": "Path Traversal",
    "SQLi": "SQL Injection",
    "RXSS": "Reflected XSS",
    "XSS": "XSS",
    "SSRF": "SSRF",
    "SSTI": "SSTI",
    "XXE": "XXE",
    "LFI": "LFI",
    "RFI": "RFI",
    "FileRead": "File Read",
    "InfoDisclosure": "Info Disclosure",
    "CWE200": "Info Disclosure",
    "CWE665": "Improper Init",
    "DoS": "DoS",
}

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def year_of(advisory_id):
    """Year embedded in an advisory id (CVE-2026-1234 -> 2026), else None."""
    match = re.search(r"-(\d{4})-", advisory_id or "")
    return int(match.group(1)) if match else None


def load_entries(root=REPO_ROOT):
    """Every entry in the archive, annotated with what the generators need.

    Adds these underscore-prefixed keys, which are derived and never written
    back to disk:

        _dir      path relative to the repository root
        _product  the product field, falling back to the top-level directory
        _year     year from the advisory id, 0 when it has none
        _score    CVSS base score, or None
        _flat     True for the few entries that predate the
                  <Product>/<CLASS> - <ID> layout and sit at the root

    A metadata.json that will not parse is reported and skipped rather than
    aborting the run: one bad file should not stop every index from rebuilding.
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in SKIP_DIRS]
        if "metadata.json" not in filenames:
            continue
        path = os.path.join(dirpath, "metadata.json")
        try:
            with open(path, encoding="utf-8") as handle:
                entry = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            print(f"warning: skipping {os.path.relpath(path, root)}: {error}", file=sys.stderr)
            continue
        relative = os.path.relpath(dirpath, root)
        entry["_dir"] = relative
        entry["_product"] = entry.get("product") or relative.split(os.sep)[0]
        entry["_year"] = year_of(entry.get("id")) or 0
        entry["_score"] = (entry.get("cvss") or {}).get("score")
        entry["_flat"] = os.sep not in relative
        entries.append(entry)
    return entries


def sort_key(entry):
    """Newest first, then hardest hitting, then by id for a stable order.

    Entries with no score sort below scored ones rather than above: an unscored
    advisory is not evidence of low severity, but putting it first would claim
    prominence the data does not support.
    """
    return (
        -entry["_year"],
        -(entry["_score"] if entry["_score"] is not None else -1),
        entry.get("id") or "",
    )


def by_product_key(entry):
    """Alphabetical by product, then class, then id — for the indices."""
    return (entry["_product"].lower(), entry.get("class") or "", entry.get("id") or "")


def entry_url(entry):
    """Absolute GitHub URL for an entry's folder, escaped for markdown and HTML.

    Quoting the parentheses matters: an unescaped ")" inside a markdown link
    target ends the link early, and several products have them in their names
    (`HFS (HttpFileServer)`).
    """
    quoted = urllib.parse.quote(entry["_dir"].replace(os.sep, "/"))
    return f"{REPO_URL}/tree/main/{quoted}"


def relative_link(entry):
    """Repo-relative markdown link target, for the in-repo indices."""
    return "./" + urllib.parse.quote(entry["_dir"].replace(os.sep, "/"))


def class_label(entry):
    """Readable name for an entry's vulnerability class."""
    raw = entry.get("class") or "-"
    return CLASS_LABELS.get(raw, raw)


def headline(entry):
    """Display text for an entry.

    `summary` comes from the upstream databases and is sometimes truncated or
    misspelled there. `headline` is an optional hand-written override for the
    cases worth polishing, without losing what upstream actually said.
    """
    return (entry.get("headline") or entry.get("summary") or "").strip()
