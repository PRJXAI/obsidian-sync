#!/usr/bin/env python3
"""Review drift, check links, and explicitly create/update/delete authored Markdown.

No network/LLM calls. Deletion requires a reason, --yes, no inbound links, and git history.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/review.json"


def doc_path(value):
    candidate = ROOT / value
    path = candidate.resolve()
    if not path.is_relative_to(ROOT / "docs") or path.suffix != ".md" or candidate.is_symlink():
        raise SystemExit("Only non-symlink Markdown within docs/ is permitted")
    return path


def links(path):
    for match in re.finditer(r"\[[^\]]*\]\(([^\s)#]+)(?:#[^)]*)?\)", path.read_text()):
        target = match.group(1)
        if "://" not in target and not target.startswith(("mailto:", "#")):
            yield (path.parent / target).resolve()


def markdown():
    return [ROOT / "README.md", ROOT / "AGENTS.md", *sorted((ROOT / "docs").rglob("*.md"))]


def fingerprints():
    folders = ("src", "tests", "config", "deploy", ".github", ".agents", "scripts", "examples")
    files = [ROOT / p for p in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "Dockerfile", ".dockerignore", ".gitignore", ".env.example", "deny.toml", "AGENTS.md", "LICENSE")]
    files += list(ROOT.glob("docker-compose*.yml"))
    files += [p for folder in folders for p in (ROOT / folder).rglob("*") if p.is_file() and "__pycache__" not in str(p)]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files) if p.exists()}


parser = argparse.ArgumentParser(description=__doc__)
commands = parser.add_subparsers(dest="command", required=True)
commands.add_parser("check")
review = commands.add_parser("review")
review.add_argument("--reason", required=True)
create = commands.add_parser("create")
create.add_argument("path")
create.add_argument("--title", required=True)
update = commands.add_parser("update")
update.add_argument("path")
update.add_argument("--from-file", required=True)
delete = commands.add_parser("delete")
delete.add_argument("path")
delete.add_argument("--reason", required=True)
delete.add_argument("--yes", action="store_true")
args = parser.parse_args()

if args.command == "create":
    path = doc_path(args.path)
    if path.exists():
        raise SystemExit("Document already exists; use update")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {args.title}\n\nStatus: draft. Add verified behavior, sources, limits and reproduction commands.\n")
elif args.command == "update":
    path = doc_path(args.path)
    if not path.is_file():
        raise SystemExit("Document does not exist")
    path.write_text(Path(args.from_file).read_text())
elif args.command == "delete":
    path = doc_path(args.path)
    if not args.yes or not args.reason.strip():
        raise SystemExit("Deletion requires --yes and a reason")
    inbound = [str(p.relative_to(ROOT)) for p in markdown() if p != path and p.exists() and path in links(p)]
    if inbound:
        raise SystemExit("Remove/update inbound links first: " + ", ".join(inbound))
    relative = str(path.relative_to(ROOT))
    tracked = subprocess.run(["git", "cat-file", "-e", f"HEAD:{relative}"], cwd=ROOT, capture_output=True)
    if tracked.returncode:
        raise SystemExit("Refusing deletion without committed documentation history")
    clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", relative], cwd=ROOT)
    if clean.returncode or not path.is_file():
        raise SystemExit("Preserve/commit local document changes before deletion")
    path.unlink()
    print("Deleted", args.path, "reason:", args.reason)
elif args.command == "review":
    if not args.reason.strip():
        raise SystemExit("A real review reason is required")
    sources = [{"path": path, "sha256": digest} for path, digest in fingerprints().items()]
    MANIFEST.write_text(json.dumps({"reason": args.reason, "sources": sources}, indent=2, sort_keys=True) + "\n")
else:
    issues = []
    for path in markdown():
        if not path.exists():
            issues.append(f"missing {path.relative_to(ROOT)}")
            continue
        if "Status: draft." in path.read_text():
            issues.append(f"unreviewed draft {path.relative_to(ROOT)}")
        for target in links(path):
            if not target.is_relative_to(ROOT) or not target.exists():
                issues.append(f"broken/escaping link in {path.relative_to(ROOT)}: {target}")
    current = fingerprints()
    recorded = json.loads(MANIFEST.read_text())["sources"] if MANIFEST.exists() else []
    previous = recorded if isinstance(recorded, dict) else {entry["path"]: entry["sha256"] for entry in recorded}
    changed = sorted(p for p in current.keys() | previous.keys() if current.get(p) != previous.get(p))
    if changed:
        issues.append("Review docs against changed sources, then run docs.py review --reason ...: " + ", ".join(changed))
    if issues:
        raise SystemExit("\n".join(issues))
    print("Documentation links and reviewed source fingerprints are current")
