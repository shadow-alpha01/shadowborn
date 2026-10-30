#!/usr/bin/env python3
"""File-only Shadowborn package installer. Never invokes network/service tools."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    'usr/local/bin/shadowborn': ('target/release/shadowborn', 0o755),
    'usr/local/share/doc/shadowborn/README.md': ('README.md', 0o644),
    'usr/local/share/doc/shadowborn/LICENSE': ('LICENSE', 0o644),
    'usr/local/share/doc/shadowborn/server.example.toml': ('config/server.example.toml', 0o644),
}
for name in ('installation-server', 'client-enrollment', 'admin-recovery', 'no-logs-policy', 'validation', 'licensing'):
    FILES[f'usr/local/share/doc/shadowborn/{name}.md'] = (f'docs/{name}.md', 0o644)
MANIFEST = 'var/lib/shadowborn-package/manifest.json'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path):
    for entry in (path, *path.parents):
        try:
            m = entry.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(m.st_mode):
            raise RuntimeError('Symlink path conflict')
        if m.st_uid not in (0, os.geteuid()):
            raise RuntimeError('Untrusted path owner')
        if m.st_mode & 0o022 and not (stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and m.st_mode & stat.S_ISVTX):
            raise RuntimeError('Writable path conflict')


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_dir(path, mode=0o755):
    safe_path(path)
    if path.exists():
        if not path.is_dir():
            raise RuntimeError("Directory path conflict")
        return
    ensure_dir(path.parent)
    path.mkdir(mode=mode)
    sync_directory(path.parent)


def atomic(path, data, mode):
    safe_path(path)
    ensure_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.shadowborn-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'update', 'uninstall'))
    parser.add_argument('--destdir', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    prefix = args.destdir or Path('/')
    if not prefix.is_absolute() or '..' in prefix.parts:
        raise RuntimeError('Absolute normalized destdir required')
    if args.dry_run:
        print(f'{args.action}: owned CLI/documentation files only; networking/configuration/keys/services untouched')
        for name in FILES:
            print(prefix / name)
        return
    if prefix == Path('/') and os.geteuid() != 0:
        raise RuntimeError('Host file installation requires root')
    if prefix == Path('/') and Path('/etc/systemd/system/shadowborn-firewall.service').exists():
        raise RuntimeError('Deployed gateway found: package updates/uninstall require manual review')
    safe_path(prefix)
    manifest = prefix / MANIFEST
    safe_path(manifest)
    ensure_dir(manifest.parent, mode=0o700)
    lock_path = manifest.parent / 'lock'
    safe_path(lock_path)
    with os.fdopen(os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), 'rb+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (manifest.parent / 'pending').exists():
            raise RuntimeError('Interrupted packaging transaction: inspect pending/ backups before retry')
        previous = json.loads(manifest.read_text()) if manifest.exists() else {}
        if any(name not in FILES for name in previous):
            raise RuntimeError('Invalid ownership manifest')
        if args.action in ('update', 'uninstall') and not previous:
            raise RuntimeError('No owned installation found')
        if args.action == 'install' and previous:
            raise RuntimeError('Already installed; use update')
        content = {}
        for name, (source, mode) in FILES.items():
            target = prefix / name
            safe_path(target)
            if target.exists() and (not target.is_file() or name not in previous or digest(target.read_bytes()) != previous[name]):
                raise RuntimeError('Modified/unowned installed file retained')
            if name in previous and not target.exists():
                raise RuntimeError('Owned installed file disappeared')
            if args.action != 'uninstall':
                content[name] = ((ROOT / source).read_bytes(), mode)
        # Durable copies contain program/docs only, never keys or activity.
        pending = manifest.parent / 'pending'
        ensure_dir(pending, mode=0o700)
        atomic(pending / 'before.json', json.dumps(previous).encode(), 0o600)
        atomic(pending / 'after.json', json.dumps({name: digest(data) for name, (data, _) in content.items()}).encode(), 0o600)
        for index, name in enumerate(previous):
            atomic(pending / str(index), (prefix / name).read_bytes(), 0o600)
        try:
            if args.action == 'uninstall':
                for name in previous:
                    (prefix / name).unlink()
                    sync_directory((prefix / name).parent)
                manifest.unlink()
                sync_directory(manifest.parent)
            else:
                for name, (data, mode) in content.items():
                    atomic(prefix / name, data, mode)
                atomic(manifest, json.dumps({name: digest(data) for name, (data, _) in content.items()}).encode(), 0o600)
        except Exception:
            print('Packaging interrupted: protected before.json and copies retained in pending/', file=sys.stderr)
            raise
        shutil.rmtree(pending)
        sync_directory(manifest.parent)
        print('Package operation complete. No networking, service activation or key changes.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Packaging stopped: {error}', file=sys.stderr)
        sys.exit(1)
