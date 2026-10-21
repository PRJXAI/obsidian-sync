---
name: maintain-docs
description: Maintain this repository's authored documentation, remove stale pages safely, refresh generated configuration/source maps, and update LLM context after code changes.
---

# Maintain repository documentation

1. Read AGENTS.md, README.md, docs/llm.md, docs/consistency.md and docs/threat-model.md. Check `git diff` and `python3 scripts/docs.py check` to locate source drift and broken links.
2. Read changed implementation AND tests; do not write claims from interfaces alone. Preserve the prominent missing-plugin blocker and distinguish a build, emulator test, real-provider test and actual plugin compatibility test.
3. Update the smallest authored pages affected. Create with `python3 scripts/docs.py create docs/topic.md --title 'Topic'`; replace its draft with verified content using an editor or `docs.py update docs/topic.md --from-file FILE`. Include reproduction commands, persistent state, failure recovery and remaining limitations.
4. For stale pages, first move any still-valid information and remove inbound links. Delete only with `python3 scripts/docs.py delete docs/stale.md --reason 'Superseded by ...' --yes`. The tool refuses untracked pages, escaping/symlink targets and pages with inbound links. Never automatically delete prose based solely on age or an LLM judgment.
5. Update docs/llm.md when module ownership, commands, invariants, or blocked capabilities change. Update docs/results.md only from actual measurements. Do not include secret values, note bodies, private identifiers, or real infrastructure details.
6. Run `python3 scripts/sync-generated.py` to refresh canonical config copies and docs/source-map.md. Do not hand-edit generated copies.
7. Run Python maintenance tests and deployment rendering. Review the affected authored docs explicitly, then acknowledge source fingerprints with `python3 scripts/docs.py review --reason 'Describe what was reviewed'`. This is a review acknowledgment, not automatic content generation.
8. Run `python3 scripts/sync-generated.py --check` and `python3 scripts/docs.py check`. Include added/updated/deleted pages in the handoff. Never suppress a source-drift check without doing the review.
