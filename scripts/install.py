#!/usr/bin/env python3
"""Install the mobile-security-skill toolkit into a supported agent harness.

Two harnesses are supported, and the toolkit works in both:

  claude    Claude Code   skill -> ~/.claude/skills/mobile-security-skill/
                            agents -> ~/.claude/agents/*.md

  opencode  opencode v2   skill -> ~/.config/opencode/skills/mobile-security-skill/
                            agents -> ~/.config/opencode/agents/*.md  (opencode-native
                            frontmatter, generated from the canonical definitions)

The opencode agent files are generated on the fly from ``agents/*.md`` (see
``sync_opencode_agents.py``), so the canonical Claude Code definitions stay the
single source of truth.

Usage:
    python3 scripts/install.py --target opencode
    python3 scripts/install.py --target claude
    python3 scripts/install.py --target both
    python3 scripts/install.py --target opencode --scope project --project /path/to/repo
    python3 scripts/install.py --target both --dry-run
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sync_opencode_agents import generate  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_SOURCE = REPO_ROOT / "skills" / "mobile-security-skill"
SKILL_ID = "mobile-security-skill"


def targets(scope: str, project: Path | None, home: Path) -> dict[str, dict[str, Path]]:
    """Return, per harness, the directories to install the skill and agents into."""
    if scope == "global":
        return {
            "claude": {
                "skill": home / ".claude" / "skills" / SKILL_ID,
                "agents": home / ".claude" / "agents",
                "skill_layout": "directory",
            },
            "opencode": {
                "skill": home / ".config" / "opencode" / "skills" / SKILL_ID,
                "agents": home / ".config" / "opencode" / "agents",
                "skill_layout": "directory",
            },
        }
    root = (project or REPO_ROOT).resolve()
    return {
        "claude": {
            "skill": root / ".claude" / "skills" / SKILL_ID,
            "agents": root / ".claude" / "agents",
            "skill_layout": "directory",
        },
        "opencode": {
            "skill": root / ".opencode" / "skills" / SKILL_ID,
            "agents": root / ".opencode" / "agents",
            "skill_layout": "directory",
        },
    }


def install_skill(destination: Path, dry_run: bool) -> None:
    """Copy the skill bundle (SKILL.md + references/) to its destination."""
    if dry_run:
        print(f"  would copy {SKILL_SOURCE.relative_to(REPO_ROOT)} -> {destination}")
        return
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(SKILL_SOURCE, destination)
    print(f"  installed skill -> {destination}")


def install_agents(destination: Path, harness: str, dry_run: bool) -> None:
    """Install agent definitions in the format the target harness expects."""
    if harness == "claude":
        sources = sorted((REPO_ROOT / "agents").glob("*.md"))
        if dry_run:
            for source in sources:
                print(f"  would copy {source.relative_to(REPO_ROOT)} -> {destination / source.name}")
            return
        destination.mkdir(parents=True, exist_ok=True)
        for source in sources:
            shutil.copy2(source, destination / source.name)
        print(f"  installed {len(sources)} agents -> {destination}")
        return

    rendered = generate()
    if dry_run:
        for name in sorted(rendered):
            print(f"  would write {destination / name}")
        return
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(rendered.items()):
        (destination / name).write_text(content, encoding="utf-8")
    print(f"  installed {len(rendered)} agents -> {destination}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--target",
        choices=["claude", "opencode", "both"],
        default="opencode",
        help="which harness to install into (default: opencode)",
    )
    parser.add_argument(
        "--scope",
        choices=["global", "project"],
        default="global",
        help="install for the current user (default) or into one project directory",
    )
    parser.add_argument(
        "--project",
        type=Path,
        default=None,
        help="project directory for --scope project (default: this repository)",
    )
    parser.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    args = parser.parse_args()

    if not SKILL_SOURCE.is_dir():
        raise SystemExit(f"error: skill bundle not found at {SKILL_SOURCE}")

    layout = targets(args.scope, args.project, Path.home())
    harnesses = ["claude", "opencode"] if args.target == "both" else [args.target]

    for harness in harnesses:
        paths = layout[harness]
        print(f"[{harness}] scope={args.scope}")
        install_skill(paths["skill"], args.dry_run)
        install_agents(paths["agents"], harness, args.dry_run)

    print("\nNext: start a new session in your harness (or restart it) so it picks the changes up.")
    if "opencode" in harnesses:
        print("opencode: the skill is advertised as `mobile-security-skill`; ask for an audit in plain language.")
    if "claude" in harnesses:
        print("claude: the skill is advertised as `mobile-security-skill`; ask for an audit in plain language.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
