#!/usr/bin/env python3
"""Root-only CLI exercised in a disposable chroot/user/network namespace.

All keys and profiles are synthetic lab identities and deleted with the fixture.
No root privileges or changes to host networking/services are requested.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    os.umask(0o077)
    age = os.environ.get('SHADOWBORN_AGE') or shutil.which('age')
    keygen = os.environ.get('SHADOWBORN_AGE_KEYGEN') or shutil.which('age-keygen')
    wg = shutil.which('wg')
    if not all((age, keygen, wg, shutil.which('unshare'), shutil.which('chroot'))):
        print('SKIPPED: provisioning namespace requires wg, age, age-keygen, unshare, chroot')
        return
    if subprocess.run(['unshare', '-Urn', 'true'], capture_output=True).returncode:
        print('SKIPPED: user/network namespaces unavailable')
        return
    with tempfile.TemporaryDirectory(prefix='shadowborn-provisioning-') as temporary:
        jail = Path(temporary)
        for path in ('usr/local/bin', 'usr/bin', 'etc/shadowborn', 'var/lib', 'root', 'dev'):
            (jail / path).mkdir(parents=True, exist_ok=True)
        (jail / 'root').chmod(0o700)
        for device in ('null', 'urandom'):
            (jail / 'dev' / device).touch()
        binaries = ((ROOT / 'target/release/shadowborn', 'usr/local/bin/shadowborn'),
                    (Path(wg), 'usr/bin/wg'), (Path(age), 'usr/bin/age'))
        for source, destination in binaries:
            shutil.copy2(source, jail / destination)
            linked = subprocess.run(['ldd', str(source)], capture_output=True, text=True, check=True).stdout
            for library in re.findall(r'(/[^\s()]+)', linked):
                target = jail / library.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(library, target)
        shutil.copy2(ROOT / 'config/server.example.toml', jail / 'etc/shadowborn/config.toml')
        identity = jail / 'root/operator.agekey'
        with identity.open('wb') as stream:
            subprocess.run([keygen], stdout=stream, stderr=subprocess.DEVNULL, check=True)
        identity.chmod(0o600)
        recipient = subprocess.run([keygen, '-y', str(identity)], capture_output=True, text=True, check=True).stdout.strip()

        def cli(*args, ok=True):
            result = subprocess.run(['unshare', '-Urnm', '--propagation', 'private', 'sh', '-c',
                                     'mount --bind /dev/null "$1/dev/null" && mount --bind /dev/urandom "$1/dev/urandom" && exec chroot "$@"',
                                     'lab-runner', str(jail), '/usr/local/bin/shadowborn', *args], capture_output=True, text=True, timeout=45)
            assert (result.returncode == 0) == ok, ('CLI operation failed', args[0], result.returncode, result.stderr[:180])
            return result

        cli('init', '--dry-run')
        assert not (jail / 'var/lib/shadowborn').exists()
        cli('init')
        cli('init', ok=False)
        private = subprocess.run([wg, 'genkey'], capture_output=True, check=True).stdout
        public = subprocess.run([wg, 'pubkey'], input=private, capture_output=True, check=True).stdout.decode().strip()
        cli('peer', 'add', '--name', 'synthetic', '--public-key', public)
        cli('peer', 'add', '--name', 'duplicate', '--public-key', public, ok=False)
        cli('client', 'profile', '--name', 'synthetic', '--output', '/root/client.template')
        assert '<DEVICE_PRIVATE_KEY>' in (jail / 'root/client.template').read_text()
        cli('render', '--output', '/root/review')
        cli('backup', '--recipient', recipient, '--output', '/root/backup.age')
        assert (jail / 'root/backup.age').read_bytes().startswith(b'age-encryption.org/')
        cli('peer', 'revoke', '--name', 'synthetic', '--confirm')
        cli('restore', '--input', '/root/backup.age', '--identity', '/root/operator.agekey', '--dry-run')
        cli('restore', '--input', '/root/backup.age', '--identity', '/root/operator.agekey', '--confirm')
        peers = json.loads(cli('peer', 'list').stdout)
        assert peers[0]['status'] == 'revoked'
        cli('client', 'profile', '--name', 'synthetic', '--output', '/root/revoked.template', ok=False)
        cli('peer', 'issue', '--name', 'convenience', '--recipient', recipient,
            '--bundle', '/root/issued.age', '--accept-server-key-generation')
        encrypted = (jail / 'root/issued.age').read_bytes()
        decoded = subprocess.run([age, '-d', '-i', str(identity)], input=encrypted, capture_output=True, check=True).stdout
        assert b'<DEVICE_PRIVATE_KEY>' not in decoded and b'AllowedIPs = 0.0.0.0/0, ::/0' in decoded
        (jail / 'etc/wireguard').mkdir()
        (jail / 'etc/wireguard/wg-shadowborn.conf').write_text('# deployed marker')
        cli('peer', 'revoke', '--name', 'convenience', '--confirm', ok=False)
        cli('render', '--output', '/root/deployed', ok=False)
        stored = json.loads((jail / 'var/lib/shadowborn/state.json').read_text())
        redacted = cli('peer', 'show', '--name', 'convenience', '--redacted').stdout
        assert stored['server_private_key'] not in redacted
        assert all(p['psk'] is None or p['psk'] not in redacted for p in stored['peers'])
        assert sorted(p.name for p in (jail / 'var/lib/shadowborn').iterdir()) == ['lock', 'state.json']
        print('PASS: isolated root CLI init/enrollment/export/encrypted issue/backup/restore/revocation and deployed-host guard')
        print('PASS: no activity-history files; secret output redacted; host filesystem/network untouched')


if __name__ == '__main__':
    main()
