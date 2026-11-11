#!/usr/bin/env python3
"""CVSS 3.1 base score calculator for finding records.

The score is derived mechanically from the `cvss_vector` a specialist records,
so the number in the report can always be reproduced from the vector. It does
not judge the finding: severity and confirmation status still come from
`severity-rating.md`.

Usage:
    python3 scripts/cvss31.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
"""

from __future__ import annotations

import math
import sys

METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PRIVILEGES_REQUIRED = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
REQUIRED_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest value with one decimal that is >= value."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("vector must start with CVSS:3.1/")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            raise ValueError(f"malformed or duplicate metric `{part}`")
        metrics[key] = value
    missing = [m for m in REQUIRED_METRICS if m not in metrics]
    if missing:
        raise ValueError(f"missing metric(s): {', '.join(missing)}")
    if metrics["S"] not in {"U", "C"}:
        raise ValueError("S must be U or C")
    for key in ("AV", "AC", "UI", "C", "I", "A"):
        if metrics[key] not in METRICS[key]:
            raise ValueError(f"invalid value `{metrics[key]}` for {key}")
    if metrics["PR"] not in PRIVILEGES_REQUIRED["U"]:
        raise ValueError("invalid value for PR")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    scope_changed = m["S"] == "C"
    pr = PRIVILEGES_REQUIRED["C" if scope_changed else "U"][m["PR"]]
    iss = 1 - (1 - METRICS["C"][m["C"]]) * (1 - METRICS["I"][m["I"]]) * (1 - METRICS["A"][m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * METRICS["AV"][m["AV"]] * METRICS["AC"][m["AC"]] * pr * METRICS["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity_band(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    try:
        score = base_score(argv[1])
    except ValueError as exc:
        print(f"invalid: {exc}")
        return 1
    print(f"{score} ({severity_band(score)})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
