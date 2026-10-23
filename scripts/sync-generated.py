#!/usr/bin/env python3
"""Generate deployment config copies and the LLM source map. Never rewrite authored docs."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
outputs = {
    ROOT / "deploy/kustomize/base/config.toml": (ROOT / "config/filesystem.toml").read_text(),
}
for provider in ("s3", "gcs", "azure"):
    outputs[ROOT / f"deploy/kustomize/overlays/{provider}/config.toml"] = (ROOT / f"config/{provider}.toml").read_text()
paths = {str(p.relative_to(ROOT)) for folder in ("src", "tests", "config", "scripts", "examples", "deploy", ".github", ".agents") for p in (ROOT / folder).rglob("*") if p.is_file() and "__pycache__" not in str(p) and "node_modules" not in p.parts}
paths.update(str(p.relative_to(ROOT)) for p in outputs)
paths = sorted(paths)
outputs[ROOT / "docs/source-map.md"] = "# Generated source map\n\nRun `python3 scripts/sync-generated.py` after moving source files.\n\n" + "".join(f"- `{p}`\n" for p in paths)
failed = []
for path, text in outputs.items():
    if args.check:
        if not path.exists() or path.read_text() != text:
            failed.append(str(path.relative_to(ROOT)))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
if failed:
    raise SystemExit("Stale generated documentation/configuration: " + ", ".join(failed))
