#!/usr/bin/env python3
"""Generate the managed sections of the profile README.

Three blocks, each spliced between its own pair of marker comments:

    <!-- exploit-development:start -->   from every entry's metadata.json
    <!-- bug-bounty:start -->           from data/profile.json
    <!-- certifications:start -->       from data/profile.json

Exploits are ordered year descending then CVSS descending, so the most recent
and most severe work reads first and nothing needs reordering by hand. The
bug bounty and certification figures come from the same profile.json that feeds
wolfhacking.com.ar, so the site and the README cannot disagree about them.

    python3 tools/gen_profile_section.py                       # print to stdout
    python3 tools/gen_profile_section.py --write ../README.md  # splice into a README
    python3 tools/gen_profile_section.py --write <p> --check    # exit 1 if stale

The markers are left in place, so the same command is safe to re-run.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archive import (  # noqa: E402
    REPO_URL,
    SEVERITY_ORDER,
    class_label,
    entry_url,
    load_entries,
    sort_key,
)

START_MARKER = "<!-- exploit-development:start -->"
END_MARKER = "<!-- exploit-development:end -->"

# The profile README carries three generated blocks. Certifications and bug
# bounty come from data/profile.json, the same file that feeds the website, so
# the two never disagree about a percentage or a reputation score.
PROFILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "profile.json")
BOUNTY_MARKERS = ("<!-- bug-bounty:start -->", "<!-- bug-bounty:end -->")
CERT_MARKERS = ("<!-- certifications:start -->", "<!-- certifications:end -->")

# Years rendered as their own visible table. Everything older is collapsed.
FEATURED_YEARS = (2026,)
# Recent-but-not-current years show only their strongest entries up front.
SELECTED_YEAR = 2025
SELECTED_LIMIT = 10


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


MONTHS = {
    "01": "January", "02": "February", "03": "March", "04": "April",
    "05": "May", "06": "June", "07": "July", "08": "August",
    "09": "September", "10": "October", "11": "November", "12": "December",
}


def load_profile():
    """Facts shared with the website: certifications, bug bounty, advisories."""
    with open(PROFILE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def pretty_date(value):
    """'2026-07' -> 'July 2026'."""
    if not value:
        return ""
    parts = str(value).split("-")
    month = MONTHS.get(parts[1]) if len(parts) > 1 else None
    return f"{month} {parts[0]}" if month else parts[0]


def render_bounty(profile):
    """The bug bounty tables: platform stats plus published advisories."""
    bb = profile.get("bugBounty", {})
    h1 = bb.get("hackerone", {})
    cs = bb.get("cyscope", {})
    advisories = profile.get("advisories", [])

    lines = [BOUNTY_MARKERS[0], "## bug bounty", "", "| Platform | Stats |", "|----------|-------|"]

    if h1:
        handle = f"[`{h1['handle']}`]({h1['url']})" if h1.get("url") else f"`{h1.get('handle')}`"
        lines.append(
            f"| **HackerOne** · {handle} | 🎯 Signal **{h1['signal']:.1f}** "
            f"({h1['signalPercentile']}th pct) · Impact **{h1['impact']:.1f}** "
            f"({h1['impactPercentile']}th pct) · **{h1['reputation']}** rep · "
            f"**{h1['credits']}** credited · **{h1['thanks']}** thanks |"
        )
    if cs:
        handle = f"[`{cs['handle']}`]({cs['url']})" if cs.get("url") else f"`{cs.get('handle')}`"
        lines.append(
            f"| **CyScope** · {handle} | 🏆 Rank **#{cs['rank']}** · **{cs['points']} pts** · "
            f"**{cs['vulns']} vulns** · **{cs['accuracy']}%** accuracy · "
            f"avg severity **{cs['avgSeverity']}** |"
        )

    if advisories:
        sole = sum(1 for a in advisories if a.get("soleCredit"))
        shared = len(advisories) - sole
        counts = f"{len(advisories)} advisories"
        if sole:
            counts += f" · {sole} sole credit"
        if shared:
            counts += f" · {shared} co-credited"

        lines += [
            "",
            "### 🛡️ Security Research & Disclosures",
            "",
            f"*{counts}.*",
            "",
            "| ID | Target | Severity | Fixed in | Finding |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for a in advisories:
            # A shared credit is labelled as such. Anyone opening the advisory
            # sees every reporter on it, so the table has to match the source.
            credit = "" if a.get("soleCredit") else f" *(co-credited, {a.get('reporters', '?')} reporters)*"
            score = f"{a['score']}" if a.get("score") is not None else "—"
            lines.append(
                f"| [{a['id']}]({a['url']}) | {a['product']} | "
                f"{a.get('severityLabel') or a.get('severity')} {score} | "
                f"`{a['fixed']}` | {a['title']}{credit} |"
            )

    lines.append("")
    lines.append(BOUNTY_MARKERS[1])
    return "\n".join(lines)


def render_certifications(profile):
    """Certification table, newest first: what is pending, then everything
    earned — degrees, exams and Pro Labs interleaved by date rather than
    grouped by kind, so the table reads as one timeline."""
    certs = profile.get("certifications", {})
    lines = [CERT_MARKERS[0], "## certifications", "", "| Badge | Name | Status |", "|-------|------|--------|"]

    # Pending work sits on top: an exam about to be sat is the most recent
    # thing that happened, and it has no date to sort it by.
    for cert in certs.get("inProgress", []):
        # An exam sat and awaiting the result is neither earned nor a mid-study
        # percentage, so it gets its own status instead of a 🔄 progress bar.
        if cert.get("status") == "awaiting":
            lines.append(f"| 🟧 {cert['id']} | {cert['name']} | ⏳ Awaiting results |")
        elif cert.get("status") == "ready":
            # Coursework finished but the exam not sat yet. Showing this as
            # "100%" alongside mid-study percentages read as already certified.
            lines.append(f"| 🟩 {cert['id']} | {cert['name']} | ✅ Ready to sit |")
        else:
            lines.append(f"| 🟦 {cert['id']} | {cert['name']} | 🔄 {cert['progress']}% |")

    earned = []
    for cert in certs.get("earned", []):
        name = cert["name"]
        if cert.get("badge"):
            name = f"[{name}]({cert['badge']})"
        earned.append((cert.get("date") or "", f"| 🟩 {cert['id']} | {name} | ✅ {pretty_date(cert.get('date')) or 'Earned'} |"))

    for lab in certs.get("proLabs", []):
        earned.append((lab.get("date") or "", f"| 🧪 {lab['name']} | HTB Pro Lab | ✅ {pretty_date(lab.get('date')) or 'Completed'} |"))

    # Newest first. An undated entry sorts last rather than to the top, which is
    # where an empty string would land it on a plain descending sort.
    earned.sort(key=lambda row: (row[0] != "", row[0]), reverse=True)
    lines += [row for _, row in earned]

    lines.append("")
    lines.append(CERT_MARKERS[1])
    return "\n".join(lines)


def splice_block(content, block, markers):
    """Replace one marked block, leaving the markers in place."""
    start, end = markers
    if start not in content or end not in content:
        return content, False
    head, _, rest = content.partition(start)
    _, _, tail = rest.partition(end)
    return f"{head}{block}{tail}", True


def build_blocks(entries, profile):
    """Every generated block, paired with the markers it belongs between."""
    return [
        (render_section(entries), (START_MARKER, END_MARKER), "exploit development"),
        (render_bounty(profile), BOUNTY_MARKERS, "bug bounty"),
        (render_certifications(profile), CERT_MARKERS, "certifications"),
    ]


def splice(readme_path, blocks):
    """Replace each marked block in a README, reporting what was missing."""
    with open(readme_path, encoding="utf-8") as handle:
        original = handle.read()

    content = original
    missing = []
    for block, markers, name in blocks:
        content, ok = splice_block(content, block, markers)
        if not ok:
            missing.append((name, markers))

    if missing:
        detail = "\n".join(f"  {name}: {m[0]} ... {m[1]}" for name, m in missing)
        raise SystemExit(
            f"error: {readme_path} is missing marker pairs for:\n{detail}\n"
            f"Add each pair around the section it should manage."
        )

    if content == original:
        print(f"{readme_path}: already up to date")
        return False
    with open(readme_path, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"{readme_path}: updated")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--write", metavar="README", help="splice into this README between markers")
    parser.add_argument("--check", action="store_true", help="exit 1 if --write target is stale")
    args = parser.parse_args()

    blocks = build_blocks(load_entries(), load_profile())

    if not args.write:
        print("\n\n".join(block for block, _, _ in blocks))
        return 0

    if args.check:
        with open(args.write, encoding="utf-8") as handle:
            content = handle.read()
        stale = [name for block, _, name in blocks if block not in content]
        if stale:
            print(f"{args.write}: stale ({', '.join(stale)})")
            return 1
        print(f"{args.write}: up to date")
        return 0

    splice(args.write, blocks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
