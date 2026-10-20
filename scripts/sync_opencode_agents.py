#!/usr/bin/env python3
"""Generate opencode-native agent definitions from the canonical Claude Code ones.

The canonical definitions live in ``agents/*.md`` with Claude Code frontmatter
(``name`` / ``description`` / ``tools``). opencode v2 uses a different agent
contract: a Markdown file under ``.opencode/agents/`` with ``mode: subagent`` and
``permissions`` rules instead of a ``tools`` allowlist.

This script converts one contract into the other so the same 18 specialists run
under both harnesses. It never modifies ``agents/*.md``.

Usage:
    python3 scripts/sync_opencode_agents.py            # regenerate .opencode/agents/
    python3 scripts/sync_opencode_agents.py --check    # exit 1 if out of date (CI)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = REPO_ROOT / "agents"
TARGET_DIR = REPO_ROOT / ".opencode" / "agents"

# Claude Code tool -> opencode permission action. The `tools:` list in a Claude
# Code agent file is an allowlist of tools; opencode's `permissions` is an
# ordered rule list, so a tool that is NOT granted has to be denied explicitly.
#
# `Write` and `Edit` are separate Claude Code tools but share opencode's `edit`
# action (which also covers `write` and `patch`), so a Claude Code grant of
# "Write but not Edit" becomes "edit allowed" here. The "never modify the
# target source" constraint therefore stays a behavioural rule in the agent
# body rather than a permission deny. See README.md for the full table.
TOOL_ACTIONS = {
    "Read": "read",
    "Grep": "grep",
    "Glob": "glob",
    "Bash": "shell",
    "Write": "edit",
}

# Tools that no agent in this kit is granted, and which opencode would
# otherwise leave at their default (ask). Denying them keeps the grant
# equivalent to the Claude Code one.
ALWAYS_DENIED_ACTIONS = ["webfetch", "websearch", "subagent", "question"]

GENERATED_HEADER = (
    "<!-- GENERATED from agents/{source} by scripts/sync_opencode_agents.py. "
    "Do not edit by hand: run `python3 scripts/sync_opencode_agents.py`. -->"
)


def split_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Return (frontmatter fields, body) for a Markdown file with YAML frontmatter."""
    if not text.startswith("---"):
        raise ValueError("missing frontmatter: file does not start with '---'")
    end = text.find("\n---", 3)
    if end == -1:
        raise ValueError("missing frontmatter: no closing '---'")
    block = text[3:end].lstrip("\n")
    body = text[end + len("\n---") :].lstrip("\n")
    fields: dict[str, str] = {}
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body


def parse_tools(value: str) -> list[str]:
    return [tool.strip() for tool in value.split(",") if tool.strip()]


def build_permissions(tools: list[str]) -> list[dict[str, str]]:
    """Map a Claude Code `tools:` allowlist to opencode permission rules."""
    granted = {TOOL_ACTIONS[tool] for tool in tools if tool in TOOL_ACTIONS}
    rules: list[dict[str, str]] = []
    for action in ("read", "grep", "glob", "shell", "edit"):
        effect = "allow" if action in granted else "deny"
        rules.append({"action": action, "resource": "*", "effect": effect})
    for action in ALWAYS_DENIED_ACTIONS:
        rules.append({"action": action, "resource": "*", "effect": "deny"})
    return rules


def render_agent(source_name: str, fields: dict[str, str], body: str) -> str:
    description = fields.get("description", "").strip()
    if not description:
        raise ValueError(f"{source_name}: missing description")

    tools = parse_tools(fields.get("tools", ""))
    unknown = [tool for tool in tools if tool not in TOOL_ACTIONS]
    if unknown:
        raise ValueError(f"{source_name}: unmapped tool(s) in 'tools:': {', '.join(unknown)}")

    permissions = build_permissions(tools)

    lines = [
        "---",
        f"description: {description}",
        "mode: subagent",
        "permissions:",
    ]
    for rule in permissions:
        lines.append(f"  - action: {rule['action']}")
        lines.append(f"    resource: \"{rule['resource']}\"")
        lines.append(f"    effect: {rule['effect']}")
    lines.append("---")
    lines.append("")
    lines.append(GENERATED_HEADER.format(source=source_name))
    lines.append("")
    lines.append(body.rstrip())
    lines.append("")
    return "\n".join(lines)


def collect_sources() -> list[tuple[str, str]]:
    """Return [(source filename, file contents)] for every canonical agent."""
    if not SOURCE_DIR.is_dir():
        raise SystemExit(f"error: {SOURCE_DIR} not found")
    sources = []
    for path in sorted(SOURCE_DIR.glob("*.md")):
        sources.append((path.name, path.read_text(encoding="utf-8")))
    if not sources:
        raise SystemExit(f"error: no agent definitions found in {SOURCE_DIR}")
    return sources


def generate() -> dict[str, str]:
    """Return {target filename: rendered contents} for every agent."""
    rendered: dict[str, str] = {}
    for source_name, text in collect_sources():
        fields, body = split_frontmatter(text)
        agent_id = fields.get("name", "").strip() or Path(source_name).stem
        if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", agent_id):
            raise SystemExit(f"error: {source_name}: agent id {agent_id!r} is not kebab-case")
        rendered[f"{agent_id}.md"] = render_agent(source_name, fields, body)
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify the generated files are up to date instead of writing them")
    args = parser.parse_args()

    rendered = generate()

    if args.check:
        stale = []
        for name, content in sorted(rendered.items()):
            path = TARGET_DIR / name
            if not path.exists():
                stale.append(f"{name} (missing)")
            elif path.read_text(encoding="utf-8") != content:
                stale.append(f"{name} (out of date)")
        extra = []
        if TARGET_DIR.is_dir():
            extra = [p.name for p in sorted(TARGET_DIR.glob("*.md")) if p.name not in rendered]
        if stale or extra:
            for item in stale:
                print(f"stale: {item}", file=sys.stderr)
            for item in extra:
                print(f"unexpected: {item} (no matching source agent)", file=sys.stderr)
            print("\nrun: python3 scripts/sync_opencode_agents.py", file=sys.stderr)
            return 1
        print(f"ok: {len(rendered)} opencode agent definitions up to date")
        return 0

    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(rendered.items()):
        path = TARGET_DIR / name
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)}")

    # Drop generated files whose source agent is gone.
    for path in sorted(TARGET_DIR.glob("*.md")):
        if path.name not in rendered:
            path.unlink()
            print(f"removed {path.relative_to(REPO_ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
