#!/usr/bin/env python3
"""Fill in missing severity and CVSS data in every entry's metadata.json.

Roughly half the archive was recorded before the upstream databases published
scores, so those entries carry a null `cvss` or an empty `severity`. This walks
every metadata.json and tries three sources, in order of how much each one
gives us:

  1. GitHub Advisories  - severity, numeric score and vector in one response
  2. OSV                - vector only; the score is derived locally (tools/cvss.py)
  3. NVD                - vector and score, but heavily rate limited

Only empty fields are filled. Values already in the file are never overwritten,
so a score you set by hand survives every later run. Use --force to re-fetch.

    python3 tools/enrich_metadata.py            # fill what is missing
    python3 tools/enrich_metadata.py --dry-run  # report without writing
    python3 tools/enrich_metadata.py --force    # re-fetch every entry
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cvss import V4_MARKERS, base_score, cvss_version, parse_vector, severity_for  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER_AGENT = "verified-exploits-enrich/1.0"
TIMEOUT = 20


def get_json(url, headers=None):
    """GET a JSON document, returning None on any HTTP or decode failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.load(response)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return None


def from_github(advisory_id):
    """Look the advisory up in the GitHub Advisory Database.

    Queries by CVE id when we have one, otherwise treats the id as a GHSA.
    A GITHUB_TOKEN in the environment raises the rate limit from 60/h to 5000/h.
    """
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if advisory_id.startswith("GHSA-"):
        payload = get_json(f"https://api.github.com/advisories/{advisory_id}", headers)
        advisory = payload if isinstance(payload, dict) and "cvss" in payload else None
    else:
        payload = get_json(
            f"https://api.github.com/advisories?cve_id={advisory_id}&per_page=1", headers
        )
        advisory = payload[0] if isinstance(payload, list) and payload else None

    if not advisory:
        return None
    cvss = advisory.get("cvss") or {}
    vector, score = cvss.get("vector_string"), cvss.get("score")
    severity = (advisory.get("severity") or "").upper() or None
    if not vector and score is None and not severity:
        return None
    return {
        "vector": vector,
        "score": score,
        "severity": severity,
        "version": cvss_version(vector) if vector else None,
        "source": "github",
    }


def from_osv(advisory_id):
    """Look the advisory up in OSV, deriving the score from its vector.

    OSV lists severity as vector strings only. CVSS v4.0 vectors need the
    macrovector lookup tables to score, so a v4-only entry yields no score and
    we record the vector alone rather than guess a number.
    """
    payload = get_json(f"https://api.osv.dev/v1/vulns/{advisory_id}")
    if not isinstance(payload, dict) or "severity" not in payload:
        return None
    vectors = [item.get("score") for item in (payload.get("severity") or []) if item.get("score")]
    if not vectors:
        return None
    # Prefer a v3 vector: it is the one we can score locally.
    vector = next((v for v in vectors if "CVSS:3" in v), vectors[0])
    score = base_score(vector)
    return {
        "vector": vector,
        "score": score,
        "severity": severity_for(score),
        "version": cvss_version(vector),
        "source": "osv",
    }


def from_nvd(advisory_id):
    """Last resort: NVD. Rate limited to 5 requests per 30s without an API key."""
    if not advisory_id.startswith("CVE-"):
        return None
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    payload = get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={advisory_id}", headers
    )
    if not isinstance(payload, dict):
        return None
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    metrics = ((vulnerabilities[0].get("cve") or {}).get("metrics")) or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            if data.get("baseScore") is None:
                continue
            return {
                "vector": data.get("vectorString"),
                "score": data.get("baseScore"),
                "severity": (data.get("baseSeverity") or "").upper() or None,
                "version": data.get("version") or cvss_version(data.get("vectorString")),
                "source": "nvd",
            }
    return None


def lookup_ids(entry):
    """Ids worth querying for one entry: its own first, then its CVE aliases.

    Entries filed under a vendor identifier (ADV190005, ZDI-...) are absent from
    every database here, while the CVE recorded alongside them as an alias is
    not. CVE aliases come before GHSA ones because NVD only understands CVEs.
    """
    primary = entry.get("id") or ""
    aliases = [a for a in (entry.get("aliases") or []) if a and a != primary]
    cves = [a for a in aliases if a.startswith("CVE-")]
    others = [a for a in aliases if not a.startswith("CVE-")]
    return ([primary] if primary else []) + cves + others


def needs_enrichment(entry):
    """True when severity, score or vector is missing from an entry."""
    cvss = entry.get("cvss") or {}
    return not entry.get("severity") or cvss.get("score") is None or not cvss.get("vector")


def local_backfill(entry):
    """Derive what we can from data already in the file, with no network call.

    An entry that has a vector but no score, or a score but no severity, can be
    completed offline. Doing this first keeps API calls for entries that
    genuinely need them.
    """
    changed = []
    cvss = dict(entry.get("cvss") or {})
    vector = cvss.get("vector")

    if vector and cvss.get("score") is None:
        score = base_score(vector)
        if score is not None:
            cvss["score"] = score
            changed.append("cvss.score")
    if vector and not cvss.get("version"):
        version = cvss_version(vector)
        if version:
            cvss["version"] = version
            changed.append("cvss.version")
    if not entry.get("severity") and cvss.get("score") is not None:
        severity = severity_for(cvss["score"])
        if severity:
            entry["severity"] = severity
            changed.append("severity")
    if changed:
        entry["cvss"] = cvss
    return changed


def reconcile(entry):
    """Make `severity` agree with the recorded score.

    The three sources disagree: NVD returned "UNKNOWN" for one entry, and where
    a score comes from one database and the qualitative rating from another the
    two can land in different bands (8.8 tagged CRITICAL, 9.8 tagged HIGH). The
    CVSS v3.1 severity scale is a fixed function of the score, so whenever a
    score is present it decides the rating. Entries with no score keep whatever
    rating upstream gave them.
    """
    cvss = entry.get("cvss") or {}
    score = cvss.get("score")
    if score is None:
        return []
    expected = severity_for(score)
    current = (entry.get("severity") or "").upper()
    if not expected or current == expected:
        return []
    entry["severity"] = expected
    return [f"severity {current or 'empty'}->{expected}"]


def normalize_version(entry):
    """Correct `cvss.version` only where the vector itself contradicts it.

    A prefixless v3 vector is scored with the v3.1 formulas, but that is a
    default, not evidence: an entry that records 3.0 stays 3.0, since v3.0 and
    v3.1 base scores agree anyway. Only two cases are real errors worth fixing -
    a vector whose own CVSS:x.y prefix disagrees with the field, and a v4 vector
    filed under a v3 version because it was recorded without its prefix.
    """
    cvss = dict(entry.get("cvss") or {})
    vector = cvss.get("vector")
    if not vector:
        return []
    metrics, declared = parse_vector(vector)
    actual = declared or ("4.0" if any(m in metrics for m in V4_MARKERS) else None)
    if not actual or cvss.get("version") == actual:
        return []
    previous = cvss.get("version")
    cvss["version"] = actual
    entry["cvss"] = cvss
    return [f"cvss.version {previous or 'empty'}->{actual}"]


def apply_remote(entry, found, force):
    """Merge a lookup result into an entry, leaving existing values alone."""
    changed = []
    cvss = dict(entry.get("cvss") or {})

    if found.get("vector") and (force or not cvss.get("vector")):
        cvss["vector"] = found["vector"]
        changed.append("cvss.vector")
    if found.get("score") is not None and (force or cvss.get("score") is None):
        cvss["score"] = found["score"]
        changed.append("cvss.score")
    if found.get("version") and (force or not cvss.get("version")):
        cvss["version"] = found["version"]
        changed.append("cvss.version")
    if found.get("severity") and (force or not entry.get("severity")):
        entry["severity"] = found["severity"]
        changed.append("severity")

    if changed:
        entry["cvss"] = cvss
        source = entry.get("metadata_source") or ""
        tag = found["source"]
        if tag not in source:
            entry["metadata_source"] = f"{source}+{tag}" if source else tag
    return changed


def write_entry(path, entry):
    """Write an entry back, keeping the 2-space indent the archive already uses."""
    entry.pop("_path", None)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(entry, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def iter_entries():
    """Yield (path, entry) for every metadata.json in the archive, sorted."""
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "tools"]
        if "metadata.json" not in filenames:
            continue
        path = os.path.join(dirpath, "metadata.json")
        try:
            with open(path, encoding="utf-8") as handle:
                yield path, json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            print(f"  ! unreadable: {os.path.relpath(path, REPO_ROOT)}: {error}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    parser.add_argument("--force", action="store_true", help="re-fetch entries that already have data")
    parser.add_argument("--offline", action="store_true", help="local backfill only, no API calls")
    parser.add_argument("--delay", type=float, default=0.35, help="seconds between API calls")
    args = parser.parse_args()

    entries = sorted(iter_entries())
    print(f"{len(entries)} entries in archive\n")

    filled, still_missing, unchanged = [], [], 0

    for path, entry in entries:
        relative = os.path.relpath(os.path.dirname(path), REPO_ROOT)
        advisory_id = entry.get("id") or ""

        # Consistency fixes apply to every entry, including complete ones: a
        # score and rating from two different databases can disagree.
        housekeeping = normalize_version(entry) + reconcile(entry)

        if not args.force and not needs_enrichment(entry):
            if housekeeping:
                print(f"  ~ {advisory_id or relative:22} {', '.join(housekeeping)}  ({relative})")
                filled.append(relative)
                if not args.dry_run:
                    write_entry(path, entry)
            else:
                unchanged += 1
            continue

        changed = list(housekeeping) + local_backfill(entry)
        source = "local" if changed else None

        if (args.force or needs_enrichment(entry)) and not args.offline and advisory_id:
            # Entries filed under a vendor id (ADV..., ZDI-...) are unknown to
            # these databases, but their CVE alias describes the same bug, so
            # fall back to the aliases once the primary id turns up nothing.
            for candidate in lookup_ids(entry):
                for lookup in (from_github, from_osv, from_nvd):
                    found = lookup(candidate)
                    time.sleep(args.delay)
                    if not found:
                        continue
                    added = apply_remote(entry, found, args.force)
                    if added:
                        tag = found["source"]
                        if candidate != advisory_id:
                            tag = f"{tag}({candidate})"
                        changed += added
                        source = tag if source is None else f"{source}+{tag}"
                    if not needs_enrichment(entry):
                        break
                if not needs_enrichment(entry):
                    break
            # A remote score can contradict the rating it arrived with.
            changed += reconcile(entry) + normalize_version(entry)

        if changed:
            score = (entry.get("cvss") or {}).get("score")
            print(f"  + {advisory_id or relative:22} {entry.get('severity') or '?':9} {score if score is not None else '-':>5}  via {source or 'reconcile'}  ({relative})")
            filled.append(relative)
            if not args.dry_run:
                write_entry(path, entry)
        elif needs_enrichment(entry):
            print(f"  - {advisory_id or relative:22} no data upstream  ({relative})")
            still_missing.append(relative)

    print(f"\nalready complete : {unchanged}")
    print(f"enriched         : {len(filled)}{'  (dry run, nothing written)' if args.dry_run else ''}")
    print(f"still missing    : {len(still_missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
