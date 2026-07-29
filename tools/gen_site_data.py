#!/usr/bin/env python3
"""Generate site-data.js for wolfhacking.com.ar from the archive and profile.json.

The site is static, has no build step, and its CSP allows no cross-origin
requests, so it cannot read this repository at runtime. The data is committed to
the site as a plain script that assigns one global, which is the same pattern the
site already uses for its section content.

    python3 tools/gen_site_data.py                                    # stdout
    python3 tools/gen_site_data.py --write ../wolfhacking/site-data.js
    python3 tools/gen_site_data.py --write <path> --check              # exit 1 if stale

The output is a pure function of the inputs — no timestamps. A timestamp would
make the weekly sync rewrite the file every run, producing an empty commit and a
pointless deploy, and would make --check permanently report stale.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archive import (  # noqa: E402
    REPO_ROOT,
    REPO_URL,
    class_label,
    entry_url,
    headline,
    load_entries,
    sort_key,
)
from cvss import severity_for  # noqa: E402

PROFILE_PATH = os.path.join(REPO_ROOT, "data", "profile.json")
GLOBAL_NAME = "WH_DATA"
SCHEMA = 1

# Entries shown as cards. The rest go in a collapsed list.
FEATURED_COUNT = 6
# Vulnerability classes named in the summary line.
TOP_CLASSES = 6

HEADER = """/* GENERATED FILE - do not edit by hand.
 *
 * Source:     galletitaconpate/verified-exploits
 * Generator:  tools/gen_site_data.py
 * Regenerate: python3 tools/gen_site_data.py --write <site>/site-data.js
 *
 * Edits here are silently reverted by the next sync.
 */
"""


def exploit_payload(entries):
    """Counters and per-entry records for the exploit development section."""
    entries = sorted(entries, key=sort_key)

    years, classes = {}, {}
    for entry in entries:
        years[entry["_year"]] = years.get(entry["_year"], 0) + 1
        label = class_label(entry)
        classes[label] = classes.get(label, 0) + 1

    records = []
    for entry in entries:
        score = entry["_score"]
        # Severity is never emitted empty: the UI colours a badge from it. Where
        # upstream recorded none, derive it from the score, and fall back to
        # UNKNOWN only when there is no score either.
        severity = (entry.get("severity") or "").upper()
        if not severity:
            severity = (severity_for(score) or "UNKNOWN") if score is not None else "UNKNOWN"
        records.append(
            {
                "id": entry.get("id") or entry["_dir"],
                "product": entry["_product"],
                "class": entry.get("class") or "",
                "classLabel": class_label(entry),
                "severity": severity,
                "score": score,
                "year": entry["_year"],
                "poc": (entry.get("poc") or {}).get("type") == "script",
                "headline": headline(entry),
                "url": entry_url(entry),
            }
        )

    return {
        "repoUrl": REPO_URL,
        "indexUrls": {
            "byClass": f"{REPO_URL}/blob/main/INDEX_BY_CLASS.md",
            "byCwe": f"{REPO_URL}/blob/main/INDEX_BY_CWE.md",
        },
        "featuredCount": FEATURED_COUNT,
        "stats": {
            "total": len(records),
            "products": len({r["product"] for r in records}),
            "withPoc": sum(1 for r in records if r["poc"]),
            "critical": sum(1 for r in records if r["severity"] == "CRITICAL"),
            "scored": sum(1 for r in records if r["score"] is not None),
            "latestYear": max((r["year"] for r in records), default=0),
            # Pairs, not an object: the order is meaningful and must not depend
            # on how a JSON object's keys happen to be iterated.
            "years": sorted(((y, n) for y, n in years.items() if y), reverse=True),
            "classes": sorted(classes.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_CLASSES],
        },
        "entries": records,
    }


def load_profile():
    """Read data/profile.json, dropping the _comment keys used for maintainers."""
    with open(PROFILE_PATH, encoding="utf-8") as handle:
        profile = json.load(handle)

    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if not k.startswith("_")}
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    return strip(profile)


def build_payload():
    entries = [e for e in load_entries() if e.get("verified") is True]
    profile = load_profile()
    return {
        "schema": SCHEMA,
        "exploits": exploit_payload(entries),
        "certifications": profile.get("certifications", {}),
        "bugBounty": profile.get("bugBounty", {}),
        "advisories": profile.get("advisories", []),
        "profiles": profile.get("profiles", {}),
    }


def render(payload):
    """Serialise as a script assigning one global.

    ensure_ascii is on for safety rather than looks: it escapes U+2028 and
    U+2029, which are valid inside a JSON string but are line terminators inside
    a JavaScript string literal and would break the whole file.
    """
    body = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
    return f"{HEADER}window.{GLOBAL_NAME} = {body};\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--write", metavar="PATH", help="write site-data.js to this path")
    parser.add_argument("--check", action="store_true", help="exit 1 if --write target is stale")
    args = parser.parse_args()

    content = render(build_payload())

    if not args.write:
        sys.stdout.write(content)
        return 0

    existing = ""
    if os.path.exists(args.write):
        with open(args.write, encoding="utf-8") as handle:
            existing = handle.read()

    if existing == content:
        print(f"{args.write}: already up to date")
        return 0

    if args.check:
        print(f"{args.write}: stale")
        return 1

    with open(args.write, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"{args.write}: written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
