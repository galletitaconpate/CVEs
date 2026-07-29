#!/usr/bin/env python3
"""Generate the `exploit development` section of the profile README.

Reads every entry's metadata.json and renders one markdown block: the newest
advisory years as visible tables, everything older folded into a <details>.
Sorting is year descending, then CVSS descending, so the most recent and most
severe work is what a visitor reads first and nothing has to be reordered by
hand as entries are added.

    python3 tools/gen_profile_section.py                       # print to stdout
    python3 tools/gen_profile_section.py --write ../README.md   # splice into a README

Splicing replaces whatever sits between the two marker comments:

    <!-- exploit-development:start -->
    <!-- exploit-development:end -->

The markers are left in place, so the same command is safe to re-run.
"""

import argparse
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cvss import year_of  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_URL = "https://github.com/galletitaconpate/verified-exploits"
START_MARKER = "<!-- exploit-development:start -->"
END_MARKER = "<!-- exploit-development:end -->"

# Years rendered as their own visible table. Everything older is collapsed.
FEATURED_YEARS = (2026,)
# Recent-but-not-current years show only their strongest entries up front.
SELECTED_YEAR = 2025
SELECTED_LIMIT = 10

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


def load_entries():
    """Collect every entry in the archive as a flat list of dicts."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "tools"]
        if "metadata.json" not in filenames:
            continue
        path = os.path.join(dirpath, "metadata.json")
        try:
            with open(path, encoding="utf-8") as handle:
                entry = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            print(f"warning: skipping {path}: {error}", file=sys.stderr)
            continue
        relative = os.path.relpath(dirpath, REPO_ROOT)
        entry["_dir"] = relative
        entry["_product"] = entry.get("product") or relative.split(os.sep)[0]
        entry["_year"] = year_of(entry.get("id")) or 0
        entry["_score"] = (entry.get("cvss") or {}).get("score")
        entries.append(entry)
    return entries


def sort_key(entry):
    """Newest first, then hardest hitting, then by id for a stable order."""
    return (
        -entry["_year"],
        -(entry["_score"] if entry["_score"] is not None else -1),
        entry.get("id") or "",
    )


def entry_url(entry):
    """Absolute URL to an entry's folder, with spaces escaped for markdown."""
    quoted = urllib.parse.quote(entry["_dir"].replace(os.sep, "/"))
    return f"{REPO_URL}/tree/main/{quoted}"


def class_label(entry):
    raw = entry.get("class") or "-"
    return CLASS_LABELS.get(raw, raw)


def score_cell(entry):
    """CVSS cell: score plus rating, or an em dash when upstream has neither."""
    score = entry["_score"]
    severity = (entry.get("severity") or "").upper()
    if score is None:
        return f"`{severity.title()}`" if severity in SEVERITY_ORDER else "—"
    formatted = f"{score:.1f}"
    if severity == "CRITICAL":
        return f"**{formatted}**"
    return formatted


def render_table(entries):
    lines = [
        "| CVE | Target | Class | CVSS |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for entry in entries:
        identifier = entry.get("id") or entry["_dir"]
        lines.append(
            f"| [{identifier}]({entry_url(entry)}) "
            f"| {entry['_product']} "
            f"| {class_label(entry)} "
            f"| {score_cell(entry)} |"
        )
    return lines


def render_summary(entries):
    """One-line counts by year and by vulnerability class."""
    years = {}
    classes = {}
    for entry in entries:
        years[entry["_year"]] = years.get(entry["_year"], 0) + 1
        label = class_label(entry)
        classes[label] = classes.get(label, 0) + 1

    year_bits = []
    for year in sorted((y for y in years if y >= SELECTED_YEAR), reverse=True):
        year_bits.append(f"`{year}` {years[year]}")
    older = sum(count for year, count in years.items() if year < SELECTED_YEAR)
    if older:
        year_bits.append(f"`≤{SELECTED_YEAR - 1}` {older}")

    top_classes = sorted(classes.items(), key=lambda item: (-item[1], item[0]))[:6]
    class_bits = [f"{label} {count}" for label, count in top_classes]

    return " · ".join(year_bits), " · ".join(class_bits)


def render_section(entries):
    """Build the whole markdown block, markers included."""
    entries = sorted(entries, key=sort_key)
    total = len(entries)
    products = len({entry["_product"] for entry in entries})
    with_poc = sum(1 for e in entries if (e.get("poc") or {}).get("type") == "script")
    critical = sum(1 for e in entries if (e.get("severity") or "").upper() == "CRITICAL")
    year_line, class_line = render_summary(entries)

    lines = [
        START_MARKER,
        "## exploit development",
        "",
        f"**{total} reproduced exploits** across {products} products — every entry was actually "
        f"run against the affected version, never copied from a writeup. "
        f"{with_poc} ship a runnable PoC; {critical} are CVSS-critical.",
        "",
        f"→ **[galletitaconpate/verified-exploits]({REPO_URL})** · "
        f"[by CWE]({REPO_URL}/blob/main/INDEX_BY_CWE.md) · "
        f"[by class]({REPO_URL}/blob/main/INDEX_BY_CLASS.md)",
        "",
        f"{year_line}&nbsp;&nbsp;|&nbsp;&nbsp;{class_line}",
        "",
    ]

    for year in sorted(FEATURED_YEARS, reverse=True):
        current = [e for e in entries if e["_year"] == year]
        if not current:
            continue
        lines.append(f"### {year}")
        lines.append("")
        lines.extend(render_table(current))
        lines.append("")

    selected = [e for e in entries if e["_year"] == SELECTED_YEAR]
    if selected:
        shown = selected[:SELECTED_LIMIT]
        heading = f"### {SELECTED_YEAR}"
        if len(selected) > len(shown):
            heading += f" · top {len(shown)} of {len(selected)}"
        lines.append(heading)
        lines.append("")
        lines.extend(render_table(shown))
        lines.append("")

    shown_ids = {e.get("id") for e in entries if e["_year"] in FEATURED_YEARS}
    shown_ids |= {e.get("id") for e in selected[:SELECTED_LIMIT]}
    remaining = [e for e in entries if e.get("id") not in shown_ids]
    if remaining:
        lines.append("<details>")
        lines.append(
            f"<summary><b>full archive — {len(remaining)} more</b> "
            f"({SELECTED_YEAR} remainder and earlier)</summary>"
        )
        lines.append("")
        lines.extend(render_table(remaining))
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append(END_MARKER)
    return "\n".join(lines)


def splice(readme_path, section):
    """Replace the marked block in a README, or report what is missing."""
    with open(readme_path, encoding="utf-8") as handle:
        content = handle.read()

    if START_MARKER in content and END_MARKER in content:
        head, _, rest = content.partition(START_MARKER)
        _, _, tail = rest.partition(END_MARKER)
        updated = f"{head}{section}{tail}"
    else:
        raise SystemExit(
            f"error: {readme_path} has no marker pair.\n"
            f"Add these two lines around the section to be managed:\n"
            f"  {START_MARKER}\n  {END_MARKER}"
        )

    if updated == content:
        print(f"{readme_path}: already up to date")
        return False
    with open(readme_path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    print(f"{readme_path}: section updated")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--write", metavar="README", help="splice into this README between markers")
    parser.add_argument("--check", action="store_true", help="exit 1 if --write target is stale")
    args = parser.parse_args()

    section = render_section(load_entries())

    if not args.write:
        print(section)
        return 0

    if args.check:
        with open(args.write, encoding="utf-8") as handle:
            content = handle.read()
        stale = section not in content
        print(f"{args.write}: {'stale' if stale else 'up to date'}")
        return 1 if stale else 0

    splice(args.write, section)
    return 0


if __name__ == "__main__":
    sys.exit(main())
