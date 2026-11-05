#!/usr/bin/env python3
"""Check an engagement's findings.jsonl against the finding schema and the rating rules.

This is a contract check, not an audit: it confirms that each record follows
``skills/mobile-security-skill/references/finding-schema.md`` and that the
Confirmed gate in ``severity-rating.md`` has its required artifacts on disk. It
never decides whether a finding is true. Problems are reported as warnings and
the exit code is 0 either way, so it can be run in CI and locally without
blocking report generation.

Usage:
    python3 scripts/validate_findings.py engagement-<slug>/
    python3 scripts/validate_findings.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCES_DIR = REPO_ROOT / "skills" / "mobile-security-skill" / "references"

STATUS_VALUES = {
    "candidate",
    "under-review",
    "confirmed",
    "potential",
    "informational",
    "false-positive",
}
FINAL_SEVERITY_VALUES = {"critical", "high", "medium", "low", "info", None}
EVIDENCE_TYPES = {"static", "dynamic", "poc"}
PLATFORMS = {"AND", "IOS", "BOTH"}

REQUIRED_FIELDS = [
    "finding_id",
    "title",
    "agent",
    "platform",
    "ref_ids",
    "masvs",
    "category",
    "attacker_model",
    "evidence",
    "severity_initial",
    "confidence_initial",
    "status",
    "final_severity",
]
ATTACKER_MODELS = {"remote", "other-app", "physical", "local-root", "none"}
ID_PATTERN = re.compile(r"^(AND|IOS|BOTH)-([A-Z0-9]{2,6})-(\d{3})$")
REF_ID_PATTERN = re.compile(r"\b([A-Z]{2,4}-\d{2,3})\b")
REF_TABLE_ID_PATTERN = re.compile(r"^\|\s*([A-Z]{2,4}-\d{2,3})\s*\|", re.MULTILINE)
REF_TABLE_ID_LOOSE = re.compile(r"^\|\s*`?([A-Z]{2,4}-\d{2,3})`?\s*\|", re.MULTILINE)

CODE_CUSTOM = "CUSTOM"


def load_known_ref_ids(references_dir: Path) -> set[str]:
    """Collect every ref ID that appears as the first cell of a table row in the references."""
    known: set[str] = set()
    for doc in references_dir.glob("*.md"):
        text = doc.read_text(encoding="utf-8")
        known.update(REF_TABLE_ID_PATTERN.findall(text))
        known.update(REF_TABLE_ID_LOOSE.findall(text))
        for heading in re.findall(r"^#{2,4} .*", text, re.MULTILINE):
            known.update(REF_ID_PATTERN.findall(heading))
    return known


def normalize_fingerprint_part(value: object) -> str:
    text = "" if value is None else str(value).lower()
    text = re.sub(r"\(.*?\)", "", text)
    text = re.sub(r"[`\"'\s]+", "", text)
    return text


def fingerprint(finding: dict) -> tuple[str, str, tuple[str, ...]]:
    component = normalize_fingerprint_part(finding.get("component")) or normalize_fingerprint_part(
        finding.get("category")
    )
    sink = normalize_fingerprint_part(finding.get("sink"))
    refs = tuple(sorted(finding.get("ref_ids") or []))
    return component, sink, refs


class Report:
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def warn(self, where: str, code: str, message: str) -> None:
        self.warnings.append(f"WARN {code} [{where}] {message}")


def check_artifact_path(engagement_root: Path, artifact: str) -> Path | None:
    """Return the path the artifact points to, or None if it is not a local file reference."""
    if not artifact or "://" in artifact:
        return None
    path_part = artifact.split(":L", 1)[0]
    candidate = Path(path_part)
    if candidate.is_absolute():
        return candidate
    for base in (engagement_root, engagement_root.parent):
        if (base / candidate).exists():
            return base / candidate
    return engagement_root / candidate


def validate_record(
    record: dict,
    where: str,
    engagement_root: Path,
    known_refs: set[str],
    report: Report,
) -> None:
    for field in REQUIRED_FIELDS:
        if field not in record:
            report.warn(where, "E-FIELD", f"missing required field `{field}`")

    finding_id = record.get("finding_id", "")
    match = ID_PATTERN.match(finding_id) if isinstance(finding_id, str) else None
    if not match:
        report.warn(where, "E-ID", f"`{finding_id}` does not match <PLATFORM>-<DOMAIN>-<NNN>")
    elif match.group(1) not in PLATFORMS:
        report.warn(where, "E-ID", f"platform `{match.group(1)}` is not one of {sorted(PLATFORMS)}")

    if record.get("platform") and record.get("platform") not in {"android", "ios", "both"}:
        report.warn(where, "E-PLATFORM", f"`platform` is `{record.get('platform')}`, expected android|ios|both")

    status = record.get("status")
    if status not in STATUS_VALUES:
        report.warn(where, "E-STATUS", f"`status` `{status}` is not in the schema enum")

    final_severity = record.get("final_severity")
    if final_severity not in FINAL_SEVERITY_VALUES:
        report.warn(where, "E-SEVERITY", f"`final_severity` `{final_severity}` is not valid")

    if record.get("attacker_model") not in ATTACKER_MODELS:
        report.warn(where, "E-ATTACKER", f"`attacker_model` `{record.get('attacker_model')}` is not valid")

    ref_ids = record.get("ref_ids") or []
    if not isinstance(ref_ids, list):
        report.warn(where, "E-REFID", "`ref_ids` must be a list")
        ref_ids = []
    if not ref_ids:
        report.warn(where, "E-REFID", "`ref_ids` is empty; cite a reference ID or use CUSTOM with notes")
    for ref in ref_ids:
        if ref == CODE_CUSTOM:
            if not str(record.get("notes", "")).strip():
                report.warn(where, "E-REFID", "`CUSTOM` ref requires a justification in `notes`")
        elif ref not in known_refs:
            report.warn(where, "E-REFID", f"`{ref}` does not appear in any reference document")

    evidence = record.get("evidence") or []
    if not isinstance(evidence, list):
        report.warn(where, "E-EVIDENCE", "`evidence` must be a list")
        evidence = []
    for index, entry in enumerate(evidence):
        if not isinstance(entry, dict):
            report.warn(where, "E-EVIDENCE", f"evidence[{index}] is not an object")
            continue
        etype = entry.get("type")
        if etype not in EVIDENCE_TYPES:
            report.warn(where, "E-EVIDTYPE", f"evidence[{index}].type `{etype}` is not static|dynamic|poc")
        artifact = entry.get("artifact")
        if artifact:
            path = check_artifact_path(engagement_root, artifact)
            if path is not None and not path.exists():
                report.warn(where, "E-ARTIFACT", f"evidence[{index}].artifact `{artifact}` does not exist")

    if status == "confirmed":
        transcript = engagement_root / "exploitation" / f"{finding_id}.md"
        if not transcript.exists():
            report.warn(where, "E-CONFIRMED", f"`confirmed` requires {transcript.relative_to(engagement_root.parent)}")
        has_dynamic = any(isinstance(e, dict) and e.get("type") == "dynamic" for e in evidence)
        has_justified_static = any(
            isinstance(e, dict) and e.get("type") == "static" and str(e.get("notes", "")).strip()
            for e in evidence
        )
        if not (has_dynamic or has_justified_static):
            report.warn(
                where,
                "E-CONFIRMED",
                "`confirmed` needs dynamic evidence, or static evidence with a `notes` justification of why it is unambiguous",
            )

    if status not in {"candidate", "under-review", "informational", None} and status in STATUS_VALUES:
        transcript = engagement_root / "exploitation" / f"{finding_id}.md"
        if not transcript.exists() and status != "informational":
            report.warn(where, "E-PANEL", f"status `{status}` without {transcript.relative_to(engagement_root.parent)}")


def validate_engagement(engagement_root: Path, report: Report) -> int:
    findings_file = engagement_root / "findings" / "findings.jsonl"
    if not findings_file.exists():
        report.warn(str(engagement_root), "E-FILE", "findings/findings.jsonl not found")
        return 0

    known_refs = load_known_ref_ids(REFERENCES_DIR)
    records: list[tuple[int, dict]] = []
    seen_ids: dict[str, int] = {}

    for line_no, raw in enumerate(findings_file.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        where = f"{findings_file.name}:{line_no}"
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            report.warn(where, "E-JSON", f"invalid JSON: {exc.msg}")
            continue
        if not isinstance(record, dict):
            report.warn(where, "E-JSON", "line is not a JSON object")
            continue
        records.append((line_no, record))

        finding_id = record.get("finding_id")
        if finding_id in seen_ids:
            report.warn(where, "E-DUP-ID", f"`{finding_id}` already used on line {seen_ids[finding_id]}")
        elif isinstance(finding_id, str):
            seen_ids[finding_id] = line_no

        validate_record(record, where, engagement_root, known_refs, report)

    by_fingerprint: dict[tuple, list[str]] = {}
    for line_no, record in records:
        if record.get("status") != "candidate":
            continue
        key = fingerprint(record)
        if not key[0] or not key[1] or not key[2]:
            continue
        by_fingerprint.setdefault(key, []).append(str(record.get("finding_id")))
    for key, ids in by_fingerprint.items():
        if len(ids) > 1:
            report.warn(
                str(findings_file.name),
                "W-DEDUP",
                f"candidates {', '.join(ids)} share a fingerprint (component/sink/ref_ids); consider merging",
            )

    return len(records)


SELF_TEST_CASES = [
    (
        "valid candidate",
        {
            "finding_id": "AND-MAN-001",
            "title": "t",
            "agent": "android-manifest-auditor",
            "platform": "android",
            "ref_ids": ["MAN-01"],
            "masvs": ["MASVS-RESILIENCE-2"],
            "category": "debug-config",
            "component": ".App",
            "sink": "debugger attach",
            "attacker_model": "physical",
            "evidence": [{"type": "static", "detail": "d", "artifact": ""}],
            "severity_initial": "high",
            "confidence_initial": "static-only",
            "status": "candidate",
            "final_severity": None,
        },
        set(),
    ),
    (
        "bad status, bad ref, bad type, bad id",
        {
            "finding_id": "and-mAN-1",
            "title": "t",
            "agent": "a",
            "platform": "android",
            "ref_ids": ["ZZZ-99"],
            "masvs": [],
            "category": "x",
            "attacker_model": "remote",
            "evidence": [{"type": "guess", "detail": "d"}],
            "severity_initial": "high",
            "confidence_initial": "static-only",
            "status": "false-positive-candidate",
            "final_severity": None,
        },
        {"E-ID", "E-STATUS", "E-REFID", "E-EVIDTYPE"},
    ),
    (
        "confirmed without transcript or dynamic evidence",
        {
            "finding_id": "AND-MAN-002",
            "title": "t",
            "agent": "a",
            "platform": "android",
            "ref_ids": ["MAN-02"],
            "masvs": [],
            "category": "x",
            "attacker_model": "physical",
            "evidence": [{"type": "static", "detail": "d"}],
            "severity_initial": "high",
            "confidence_initial": "static-only",
            "status": "confirmed",
            "final_severity": "high",
        },
        {"E-CONFIRMED", "E-PANEL"},
    ),
]


def run_self_test() -> int:
    failures = 0
    known_refs = {"MAN-01", "MAN-02"}
    for name, record, expected_codes in SELF_TEST_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            engagement = Path(tmp) / "engagement-selftest"
            (engagement / "exploitation").mkdir(parents=True)
            report = Report()
            validate_record(record, name, engagement, known_refs, report)
            found = {w.split()[1] for w in report.warnings}
            if expected_codes:
                missing = expected_codes - found
                ok = not missing
            else:
                ok = not report.warnings
            status = "ok" if ok else "FAIL"
            print(f"self-test [{status}] {name}: codes={sorted(found)}")
            if not ok:
                failures += 1
    ref_count = len(load_known_ref_ids(REFERENCES_DIR))
    if ref_count < 50:
        print(f"self-test [FAIL] reference index too small ({ref_count} IDs parsed)")
        failures += 1
    else:
        print(f"self-test [ok] reference index parsed {ref_count} IDs")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("engagement", nargs="?", type=Path, help="engagement-<slug>/ directory")
    parser.add_argument("--self-test", action="store_true", help="run the validator against built-in cases")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if args.engagement is None:
        parser.error("pass an engagement directory or --self-test")

    engagement_root = args.engagement.resolve()
    report = Report()
    count = validate_engagement(engagement_root, report)

    for warning in report.warnings:
        print(warning)
    print(f"checked {count} record(s); {len(report.warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
