"""CVSS v3.0/v3.1 base score calculation.

OSV publishes CVSS vector strings but not the numeric score, so entries whose
metadata came only from OSV end up with a vector and no score. This module
derives the base score from the vector using the formulas in the CVSS v3.1
specification, section 8.1.
"""

import math
import re

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "M": 0.22, "L": 0.22, "N": 0.00}

BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# Metrics that only exist in CVSS v4.0. Several vectors were recorded without a
# CVSS:x.y prefix, so the metric names are the only way to tell v4 from v3.
V4_MARKERS = ("AT", "VC", "VI", "VA", "SC", "SI", "SA")


def parse_vector(vector):
    """Split a CVSS vector into a metric dict, tolerating a missing prefix.

    Returns (metrics, version). Version is None when the vector carries no
    CVSS:x.y prefix, which is how several older entries were recorded.
    """
    if not vector:
        return {}, None
    version = None
    parts = []
    for chunk in vector.strip().split("/"):
        if not chunk:
            continue
        if chunk.upper().startswith("CVSS:"):
            version = chunk.split(":", 1)[1]
            continue
        parts.append(chunk)
    metrics = {}
    for chunk in parts:
        if ":" not in chunk:
            continue
        key, _, value = chunk.partition(":")
        metrics[key.strip().upper()] = value.strip().upper()
    return metrics, version


def roundup(value):
    """CVSS v3.1 Appendix A roundup: ceiling to one decimal, done on integers."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector):
    """Return the CVSS v3.x base score for a vector, or None if not computable.

    Temporal and environmental metrics (E, RL, RC, ...) are ignored: the score
    recorded in metadata.json is the base score, so a vector that carries
    E:H still yields its base value.
    """
    metrics, _ = parse_vector(vector)
    version = cvss_version(vector)
    if version and not version.startswith("3"):
        # v2 uses different weights, v4 needs the macrovector lookup tables.
        return None
    if any(metric not in metrics for metric in BASE_METRICS):
        return None
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
        exploitability = (
            8.22
            * AV[metrics["AV"]]
            * AC[metrics["AC"]]
            * pr_table[metrics["PR"]]
            * UI[metrics["UI"]]
        )
        iss = 1 - (
            (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
        )
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return roundup(min(raw, 10.0))


def severity_for(score):
    """Qualitative rating for a base score, per the CVSS v3.1 severity scale."""
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def cvss_version(vector):
    """Version a vector belongs to, inferred from its metrics when unprefixed."""
    metrics, version = parse_vector(vector)
    if version:
        return version
    if any(marker in metrics for marker in V4_MARKERS):
        return "4.0"
    if all(metric in metrics for metric in BASE_METRICS):
        return "3.1"
    return None


def year_of(advisory_id):
    """Year embedded in an advisory id (CVE-2026-1234 -> 2026), else None."""
    match = re.search(r"-(\d{4})-", advisory_id or "")
    return int(match.group(1)) if match else None
