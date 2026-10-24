"""Offline regression for both shell Trivy invocations under a non-root runner.

Command shims verify identity/capabilities; real container execution is a separate
smoke check. No production Docker daemon, credentials or vault are used here.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCKER = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
with open(os.environ['DOCKER_CALLS'], 'a') as file:
    file.write(json.dumps(args) + '\n')
layer = 'sha256:' + 'a' * 64
if args[:2] == ['image', 'inspect']:
    print('sha256:' + 'b' * 64 if '--format' in args else json.dumps([{'RootFS': {'Layers': [layer]}}]))
elif args and args[0] == 'save':
    pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'fixture')
elif args and args[0] == 'run' and any(arg.startswith('aquasec/trivy:') for arg in args):
    if '--user' not in args or args[args.index('--user') + 1] != '1001:1001':
        sys.exit(47)
    if '--cap-drop' not in args or args[args.index('--cap-drop') + 1] != 'ALL':
        sys.exit(48)
    if 'no-new-privileges' not in args or 'HOME=/tmp' not in args:
        sys.exit(49)
    reports = next(pathlib.Path(arg[:-len(':/reports')]) for arg in args if arg.endswith(':/reports'))
    report = 'trivy-builder.json' if any('/reports/trivy-builder.json' in arg for arg in args) else 'trivy.json'
    (reports / report).write_text(json.dumps({'Metadata': {'DiffIDs': [layer]}, 'Results': []}))
elif args and args[0] == 'run' and any(arg.startswith('ghcr.io/gitleaks/gitleaks:') for arg in args):
    if '--network' not in args or args[args.index('--network') + 1] != 'none':
        sys.exit(50)
    target = '/repo' if 'git' in args else '/source'
    suffix = ':' + target + ':ro'
    source = next(pathlib.Path(arg[:-len(suffix)]) for arg in args if arg.endswith(suffix))
    if (source / '.env').exists() or (source / 'data').exists() or (source / '.work').exists():
        sys.exit(51)
    if target == '/repo':
        if not (source / 'HEAD').is_file() or '--log-opts=--all' not in args:
            sys.exit(52)
        if subprocess.run(['git', '--git-dir=' + str(source), 'config', '--get', 'remote.origin.url'], capture_output=True).returncode == 0:
            sys.exit(53)
        public = subprocess.check_output(['git', '--git-dir=' + str(source), 'show', 'HEAD:Cargo.lock'])
        if not public.startswith(b'# Public command fixture'):
            sys.exit(54)
'''


class ScannerPermissions(unittest.TestCase):
    def test_shell_runtime_and_builder_scanners_use_runner_identity(self):
        self.exercise_scanners(with_history=False)

    def test_history_snapshot_excludes_ignored_canaries_and_credentials(self):
        self.exercise_scanners(with_history=True)

    def exercise_scanners(self, with_history):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'bin').mkdir()
            (root / '.work').mkdir()
            (root / 'Cargo.lock').write_text('# Public command fixture\n')
            (root / '.gitignore').write_text('.work/\n.env\ndata/\n')
            (root / '.env').write_text('SYNTHETIC_CANARY=not-a-real-secret\n')
            (root / 'data').mkdir()
            (root / 'data/private-canary.txt').write_text('synthetic fixture only\n')
            script = root / 'scripts/scan-security.sh'
            shutil.copyfile(ROOT / 'scripts/scan-security.sh', script)
            shims = {
                'docker': DOCKER,
                'id': '#!/bin/sh\necho 1001\n',
                'cargo': '#!/bin/sh\nprintf "{}\\n"\n',
            }
            for name, content in shims.items():
                target = root / 'bin' / name
                target.write_text(content)
                target.chmod(0o700)
            env = {**os.environ, 'PATH': str(root / 'bin') + os.pathsep + os.environ['PATH'], 'DOCKER_CALLS': str(root / '.work/calls.jsonl'), 'SYNC_SECURITY_BUILDER_IMAGE': '', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
            subprocess.run(['git', 'init', '-q'], cwd=root, env=env, check=True)
            if with_history:
                subprocess.run(['git', 'add', 'Cargo.lock'], cwd=root, env=env, check=True)
                commit = ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm']
                subprocess.run([*commit, 'public fixture'], cwd=root, env=env, check=True)
                # CI may check out a detached merge commit, not a named local branch.
                subprocess.run(['git', 'checkout', '--detach', '-q'], cwd=root, env=env, check=True)
                with (root / 'Cargo.lock').open('a') as file:
                    file.write('# Detached fixture revision\n')
                subprocess.run(['git', 'add', 'Cargo.lock'], cwd=root, env=env, check=True)
                subprocess.run([*commit, 'detached fixture'], cwd=root, env=env, check=True)
            result = subprocess.run(['bash', str(script)], cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in (root / '.work/calls.jsonl').read_text().splitlines()]
            trivy = [args for args in calls if args and args[0] == 'run' and any(arg.startswith('aquasec/trivy:') for arg in args)]
            self.assertEqual(len(trivy), 2)
            history = [args for args in calls if args and args[0] == 'run' and any(arg.endswith(':/repo:ro') for arg in args)]
            self.assertEqual(len(history), int(with_history))
            if with_history:
                mount = next(arg for arg in history[0] if arg.endswith(':/repo:ro'))
                self.assertNotEqual(mount, str(root) + ':/repo:ro')
            for args in trivy:
                self.assertEqual(args[args.index('--user') + 1], '1001:1001')
                self.assertFalse(any('docker.sock' in arg for arg in args))
                self.assertFalse(any('ignore-unfixed' in arg for arg in args))


if __name__ == '__main__':
    unittest.main()
