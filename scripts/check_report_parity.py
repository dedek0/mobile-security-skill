#!/usr/bin/env python3
"""Check that the English and Portuguese renderings of a report state the same facts.

It reads the four files that report-synthesizer writes into an engagement's
``report/`` directory and compares, per format (markdown and HTML):

- the finding IDs and their order,
- each finding's status, CWE, CVSS vector and CVSS score,
- the severity of each finding and the counts by severity and by status,
- the coverage status of every MASVS control.

It never judges the facts and never edits a file. Problems are printed as lines
starting with ``MISMATCH``; the exit code is 0 when the renderings agree and 1
otherwise, so it can gate a release if a caller wants it to.

Usage:
    python3 scripts/check_report_parity.py engagement-<slug>/report/
    python3 scripts/check_report_parity.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cvss31  # noqa: E402

LANGS = ("en", "pt-BR")
FORMATS = {"md": "md", "html": "html"}

HTML_FINDING_ROW = re.compile(
    r'<tr data-fact="finding" data-id="([^"]+)" data-status="([^"]*)" data-severity="([^"]*)"'
    r' data-cwe="([^"]*)" data-cvss="([^"]*)" data-score="([^"]*)"'
)
HTML_COVERAGE_ROW = re.compile(r'<tr data-fact="coverage" data-control="([^"]+)" data-coverage="([^"]*)"')

MD_FINDING_HEADING = re.compile(r"^### (AND|IOS|BOTH)-[A-Z0-9]{2,6}-\d{3}: ", re.MULTILINE)
MD_FINDING_ID = re.compile(r"^### ((?:AND|IOS|BOTH)-[A-Z0-9]{2,6}-\d{3}):", re.MULTILINE)
MD_CWE = re.compile(r"\*\*[^*]*CWE[^*]*:\*\*\s*(CWE-\d+)")
MD_CVSS = re.compile(r"\*\*[^*]*CVSS[^*]*:\*\*\s*`(CVSS:3\.1/[^`]+)`\s*=\s*([0-9.]+)")
MD_STATUS = re.compile(r"\*\*[^*]*(?:Status|Estado)[^*]*:\*\*\s*([^\n·]+?)\s*(?:·|$)", re.MULTILINE)
MD_SEVERITY = re.compile(r"\*\*[^*]*(?:Severity|Severidade)[^*]*:\*\*\s*([^\n·]+?)\s*(?:·|$)", re.MULTILINE)
MD_COVERAGE_ROW = re.compile(r"^\| (?:[^|\n]*?) \|", re.MULTILINE)


def load_html(text: str) -> dict:
    findings = [
        {"id": m[0], "status": m[1], "severity": m[2], "cwe": m[3], "cvss": m[4], "score": m[5]}
        for m in HTML_FINDING_ROW.findall(text)
    ]
    coverage = {m[0]: m[1] for m in HTML_COVERAGE_ROW.findall(text)}
    return {"findings": findings, "coverage": coverage}


def load_md(text: str) -> dict:
    blocks = re.split(r"(?m)^(?=### (?:AND|IOS|BOTH)-)", text)
    findings = []
    for block in blocks:
        head = MD_FINDING_ID.match(block)
        if not head:
            continue
        cwe = MD_CWE.search(block)
        cvss = MD_CVSS.search(block)
        status = MD_STATUS.search(block)
        severity = MD_SEVERITY.search(block)
        findings.append(
            {
                "id": head.group(1),
                "status": status.group(1).strip() if status else "",
                "severity": severity.group(1).strip() if severity else "",
                "cwe": cwe.group(1) if cwe else "",
                "cvss": cvss.group(1) if cvss else "",
                "score": cvss.group(2) if cvss else "",
            }
        )
    return {"findings": findings, "coverage": {}}


def normalize_status(value: str) -> str:
    """Map a localized label back to the schema enum so EN and PT-BR compare equal."""
    table = {
        "confirmed": "confirmed",
        "confirmado": "confirmed",
        "potential": "potential",
        "potencial": "potential",
        "informational": "informational",
        "informativo": "informational",
        "false positive": "false-positive",
        "falso positivo": "false-positive",
        "candidate": "candidate",
        "candidato": "candidate",
        "under review": "under-review",
        "em análise": "under-review",
    }
    key = re.sub(r"[`*]", "", value).strip().lower()
    return table.get(key, key)


def normalize_severity(value: str) -> str:
    table = {
        "critical": "critical", "crítica": "critical",
        "high": "high", "alta": "high",
        "medium": "medium", "média": "medium",
        "low": "low", "baixa": "low",
        "info": "info", "informativa": "info",
    }
    key = re.sub(r"[`*]", "", value).strip().lower()
    return table.get(key, key)


def normalize(data: dict, fmt: str) -> dict:
    findings = []
    for item in data["findings"]:
        item = dict(item)
        if fmt == "md":
            item["status"] = normalize_status(item["status"])
            item["severity"] = normalize_severity(item["severity"])
        findings.append(item)
    return {"findings": findings, "coverage": data["coverage"]}


def counts(findings: list[dict], key: str) -> Counter:
    return Counter(f[key] for f in findings)


def compare(name: str, left: dict, right: dict, problems: list[str]) -> None:
    left_ids = [f["id"] for f in left["findings"]]
    right_ids = [f["id"] for f in right["findings"]]
    if left_ids != right_ids:
        problems.append(f"MISMATCH {name}: finding IDs or order differ: {left_ids} vs {right_ids}")
        return

    for lf, rf in zip(left["findings"], right["findings"]):
        for field in ("status", "severity", "cwe", "cvss", "score"):
            if lf[field] != rf[field]:
                problems.append(f"MISMATCH {name} {lf['id']}: {field} `{lf[field]}` vs `{rf[field]}`")

        for label, row in (("en", lf), ("pt-BR", rf)):
            if row["cvss"]:
                try:
                    computed = cvss31.base_score(row["cvss"])
                except ValueError as exc:
                    problems.append(f"MISMATCH {name} {row['id']} ({label}): invalid CVSS `{row['cvss']}`: {exc}")
                    continue
                if row["score"] and float(row["score"]) != computed:
                    problems.append(
                        f"MISMATCH {name} {row['id']} ({label}): score {row['score']} but vector computes {computed}"
                    )

    for key in ("severity", "status"):
        if counts(left["findings"], key) != counts(right["findings"], key):
            problems.append(f"MISMATCH {name}: counts by {key} differ")

    if left["coverage"] != right["coverage"]:
        diff = sorted(set(left["coverage"].items()) ^ set(right["coverage"].items()))
        problems.append(f"MISMATCH {name}: MASVS coverage differs: {diff}")


def check(report_dir: Path) -> list[str]:
    problems: list[str] = []
    for fmt, ext in FORMATS.items():
        loaded = {}
        for lang in LANGS:
            path = report_dir / f"final-report.{lang}.{ext}"
            if not path.exists():
                problems.append(f"MISMATCH missing file: {path.name}")
                break
            text = path.read_text(encoding="utf-8")
            raw = load_html(text) if fmt == "html" else load_md(text)
            loaded[lang] = normalize(raw, fmt)
        if len(loaded) == len(LANGS):
            compare(fmt, loaded["en"], loaded["pt-BR"], problems)
    return problems


def run_self_test() -> int:
    en_html = (
        '<tr data-fact="finding" data-id="AND-MAN-001" data-status="confirmed" data-severity="high"'
        ' data-cwe="CWE-489" data-cvss="CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" data-score="5.9">'
        '<tr data-fact="coverage" data-control="MASVS-STORAGE" data-coverage="tested">'
    )
    pt_html_ok = en_html.replace('data-status="confirmed"', 'data-status="confirmed"')
    pt_html_bad = en_html.replace('data-severity="high"', 'data-severity="medium"')
    failures = 0
    for name, pt_html, expect_ok in (("agree", pt_html_ok, True), ("disagree on severity", pt_html_bad, False)):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            (report_dir / "final-report.en.html").write_text(en_html, encoding="utf-8")
            (report_dir / "final-report.pt-BR.html").write_text(pt_html, encoding="utf-8")
            for ext in ("md",):
                (report_dir / f"final-report.en.{ext}").write_text("", encoding="utf-8")
                (report_dir / f"final-report.pt-BR.{ext}").write_text("", encoding="utf-8")
            problems = check(report_dir)
            html_problems = [p for p in problems if " html" in p or p.startswith("MISMATCH html")]
            ok = (not html_problems) == expect_ok
            print(f"self-test [{'ok' if ok else 'FAIL'}] html {name}: {len(html_problems)} mismatch(es)")
            if not ok:
                failures += 1
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report_dir", nargs="?", type=Path, help="engagement-<slug>/report/ directory")
    parser.add_argument("--self-test", action="store_true", help="run the checker against built-in cases")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if args.report_dir is None:
        parser.error("pass a report directory or --self-test")

    problems = check(args.report_dir.resolve())
    for line in problems:
        print(line)
    if problems:
        print(f"{len(problems)} mismatch(es) between the English and Portuguese reports")
        return 1
    print("OK: English and Portuguese reports state the same facts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
