#!/usr/bin/env python3
"""Unprivileged CLI and file-package tests. No network mutations."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'target/release/shadowborn'


def run(args, ok=True):
    result = subprocess.run([str(x) for x in args], cwd=ROOT, text=True,
                            capture_output=True, timeout=60)
    assert (result.returncode == 0) == ok, (result.returncode, result.stderr[:300])
    return result


def main():
    config = ROOT / 'config/server.example.toml'
    with tempfile.TemporaryDirectory(prefix='shadowborn-files-') as temp:
        base = Path(temp)
        state = base / 'absent-state'
        cmd = [CLI, '--config', config, '--state-dir', state]
        for operation in (['plan', '--json'], ['init', '--dry-run'], ['apply', '--dry-run']):
            plan = json.loads(run(cmd + operation).stdout)
            assert plan['network_mutations'] is False
            assert plan['stage'] == 'PROVISIONING_ONLY'
            assert not state.exists()
        run(cmd + ['validate'])
        run(cmd + ['apply', '--confirm'], ok=False)
        run(cmd + ['client', 'lockdown', 'enable', '--confirm'], ok=False)
        assert json.loads(run(cmd + ['client', 'lockdown', 'status']).stdout)['enforced'] is False
        assert json.loads(run(cmd + ['dns', 'status']).stdout)['transport_verified'] == 'NOT_TESTED'
        if os.geteuid() != 0:
            run(cmd + ['init'], ok=False)
            assert not state.exists()
        print('PASS: dry runs create no state; unsupported/unprivileged mutations fail')
        # This guard runs before euid checks, namespace creation or any network
        # command. Calling the internal mode directly must never touch the host.
        spec = importlib.util.spec_from_file_location('namespace_lab', ROOT / 'tests/namespaces/shadowborn.py')
        lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lab)
        marker = os.environ.pop('SHADOWBORN_OUTER_NETNS', None)
        try:
            for value in (None, os.readlink('/proc/self/ns/net')):
                if value is not None:
                    os.environ['SHADOWBORN_OUTER_NETNS'] = value
                try:
                    lab.isolated()
                except RuntimeError as error:
                    assert 'outer network namespace marker' in str(error)
                else:
                    raise AssertionError('internal test mode did not reject host namespace')
        finally:
            os.environ.pop('SHADOWBORN_OUTER_NETNS', None)
            if marker is not None:
                os.environ['SHADOWBORN_OUTER_NETNS'] = marker
        print('PASS: direct/internal namespace test invocation cannot mutate host networking')
        stage = base / 'stage'
        install = [ROOT / 'scripts/install-server.sh', '--destdir', stage]
        update = [ROOT / 'scripts/update-server.sh', '--destdir', stage]
        uninstall = [ROOT / 'scripts/uninstall-server.sh', '--destdir', stage]
        run(install + ['--dry-run'])
        assert not stage.exists()
        run(install)
        assert not (stage / 'etc').exists()
        assert not (stage / 'usr/local/bin/shadowmist').exists()
        run(install, ok=False)
        run(update)
        binary = stage / 'usr/local/bin/shadowborn'
        original = binary.read_bytes()
        binary.write_bytes(original + b'changed')
        run(update, ok=False)
        run(uninstall, ok=False)
        binary.write_bytes(original)
        run(uninstall)
        assert not binary.exists()
        print('PASS: staged install/update/uninstall, conflicts and legacy separation')
        outside = base / 'outside'
        outside.mkdir()
        (stage / 'usr/local/bin/shadowborn').symlink_to(outside / 'victim')
        run(install, ok=False)
        assert not (outside / 'victim').exists()
        print('PASS: symlink destination refused')


if __name__ == '__main__':
    main()
