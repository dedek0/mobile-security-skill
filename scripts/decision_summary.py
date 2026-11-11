#!/usr/bin/env python3
"""Write findings/decision-summary.json: the decision fields of every finding, one object each.

The report-synthesizer has no Bash and reads files with a line-length cap, so a long
`findings.jsonl` record can hide the fields it needs for the report (status, final
severity, CVSS vector). This script reads the full JSONL with Python, keeps only the
fields the report needs, and writes them to a small JSON file the synthesizer can read
in one piece. It never changes a verdict: it copies the values exactly as recorded.

Usage:
    python3 scripts/decision_summary.py engagement-<slug>/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cvss31  # noqa: E402

FIELDS = [
    "finding_id",
    "title",
    "platform",
    "status",
    "severity_initial",
    "final_severity",
    "attacker_model",
    "cwe",
    "cvss_vector",
    "masvs",
    "ref_ids",
    "confidence_initial",
    "agent",
    "component",
]


def build(engagement: Path) -> list[dict]:
    source = engagement / "findings" / "findings.jsonl"
    rows: list[dict] = []
    for line_no, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        record = json.loads(raw)
        row = {field: record.get(field) for field in FIELDS}
        vector = row.get("cvss_vector")
        try:
            row["cvss_score"] = cvss31.base_score(vector) if vector else None
        except ValueError:
            row["cvss_score"] = None
        row["transcript"] = (
            f"exploitation/{row['finding_id']}.md"
            if (engagement / "exploitation" / f"{row['finding_id']}.md").exists()
            else None
        )
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("engagement", type=Path, help="engagement-<slug>/ directory")
    args = parser.parse_args()

    engagement = args.engagement.resolve()
    if not (engagement / "findings" / "findings.jsonl").exists():
        print("error: findings/findings.jsonl not found", file=sys.stderr)
        return 1

    rows = build(engagement)
    target = engagement / "findings" / "decision-summary.json"
    target.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {target.relative_to(engagement.parent)} ({len(rows)} finding(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
