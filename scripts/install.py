#!/usr/bin/env python3
"""Install skill bundles and their specialist agents into a supported agent harness.

Two harnesses are supported, and the toolkit works in both:

  claude    Claude Code   skills -> ~/.claude/skills/<skill>/
                            agents -> ~/.claude/agents/*.md

  opencode  opencode v2   skills -> ~/.config/opencode/skills/<skill>/
                            agents -> ~/.config/opencode/agents/*.md  (opencode-native
                            frontmatter, generated from the canonical definitions)

By default the `mobile-security-skill` bundle is installed. Any other bundle
under ``skills/`` can be selected with ``--skill``, or installed all at once
with ``--all-skills``. Extra bundles may be local-only and are never copied
into this repository by the installer.

The opencode agent files are generated on the fly from ``agents/*.md`` (see
``sync_opencode_agents.py``), so the canonical Claude Code definitions stay the
single source of truth.

Usage:
    python3 scripts/install.py --target opencode
    python3 scripts/install.py --target claude
    python3 scripts/install.py --target both
    python3 scripts/install.py --target claude --all-skills
    python3 scripts/install.py --target claude --skill mobile-security-skill --skill my-local-skill
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
SKILLS_DIR = REPO_ROOT / "skills"
DEFAULT_SKILL_ID = "mobile-security-skill"


def discover_skills() -> dict[str, Path]:
    """Return {skill id: bundle path} for every SKILL.md-bearing directory."""
    if not SKILLS_DIR.is_dir():
        raise SystemExit(f"error: skills directory not found at {SKILLS_DIR}")
    skills: dict[str, Path] = {}
    for path in sorted(SKILLS_DIR.iterdir()):
        if path.is_dir() and (path / "SKILL.md").is_file():
            skills[path.name] = path
    if not skills:
        raise SystemExit(f"error: no skill bundles found in {SKILLS_DIR}")
    return skills


def resolve_skills(names: list[str], all_skills: bool) -> list[tuple[str, Path]]:
    """Resolve the requested skill ids to their bundle paths, preserving order."""
    if all_skills and names:
        raise SystemExit("error: use either --skill or --all-skills, not both")

    available = discover_skills()
    selected = sorted(available) if all_skills else (names or [DEFAULT_SKILL_ID])

    missing = [name for name in selected if name not in available]
    if missing:
        known = ", ".join(sorted(available))
        raise SystemExit(
            f"error: unknown skill(s): {', '.join(missing)}\navailable skills: {known}"
        )

    return [(name, available[name]) for name in selected]


def targets(scope: str, project: Path | None, home: Path) -> dict[str, dict[str, Path]]:
    """Return, per harness, the root directories for skills and agents."""
    if scope == "global":
        return {
            "claude": {
                "skills": home / ".claude" / "skills",
                "agents": home / ".claude" / "agents",
            },
            "opencode": {
                "skills": home / ".config" / "opencode" / "skills",
                "agents": home / ".config" / "opencode" / "agents",
            },
        }
    root = (project or REPO_ROOT).resolve()
    return {
        "claude": {
            "skills": root / ".claude" / "skills",
            "agents": root / ".claude" / "agents",
        },
        "opencode": {
            "skills": root / ".opencode" / "skills",
            "agents": root / ".opencode" / "agents",
        },
    }


def install_skill(source: Path, destination: Path, dry_run: bool) -> None:
    """Copy one skill bundle (SKILL.md + references/) to its destination."""
    label = source.relative_to(REPO_ROOT)
    if dry_run:
        print(f"  would copy {label} -> {destination}")
        return
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    print(f"  installed {source.name} -> {destination}")


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
        "--skill",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "skill bundle under skills/ to install; repeat for more than one "
            f"(default: {DEFAULT_SKILL_ID})"
        ),
    )
    parser.add_argument(
        "--all-skills",
        action="store_true",
        help="install every skill bundle found under skills/",
    )
    parser.add_argument(
        "--no-agents",
        action="store_true",
        help="install only the skill bundle(s), without the specialist agents",
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

    skills = resolve_skills(args.skill, args.all_skills)
    layout = targets(args.scope, args.project, Path.home())
    harnesses = ["claude", "opencode"] if args.target == "both" else [args.target]

    for harness in harnesses:
        paths = layout[harness]
        print(f"[{harness}] scope={args.scope} skills={', '.join(name for name, _ in skills)}")
        for name, source in skills:
            install_skill(source, paths["skills"] / name, args.dry_run)
        if not args.no_agents:
            install_agents(paths["agents"], harness, args.dry_run)

    print("\nNext: start a new session in your harness (or restart it) so it picks the changes up.")
    if "opencode" in harnesses:
        print("opencode: skills are advertised by name; ask for an audit in plain language.")
    if "claude" in harnesses:
        print("claude: skills are advertised by name; ask for an audit in plain language.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
