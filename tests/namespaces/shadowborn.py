#!/usr/bin/env python3
"""Synthetic kernel WireGuard/nft tests in disposable user+network namespaces.

No real Internet, host firewall, host routes or persistent activity captures.
Namespace subprocesses die on exit; veth links vanish with their namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def run(args, *, data=None, ok=True, timeout=30):
    result = subprocess.run([str(x) for x in args], input=data,
                            capture_output=True, timeout=timeout)
    if ok and result.returncode:
        # Never print wg key material/config or raw subprocess output.
        raise RuntimeError(f'Lab command failed: {Path(args[0]).name} (exit {result.returncode})')
    return result


def isolated():
    outer_namespace = os.environ.get('SHADOWBORN_OUTER_NETNS')
    if not outer_namespace or outer_namespace == os.readlink('/proc/self/ns/net'):
        raise RuntimeError('Refusing execution without a distinct outer network namespace marker')
    if os.geteuid() != 0:
        raise RuntimeError('Expected root mapped only inside the disposable user namespace')
    children = []
    with tempfile.TemporaryDirectory(prefix='shadowborn-netns-') as temp:
        base = Path(temp)
        try:
            for _ in range(2):
                child = subprocess.Popen(['unshare', '--net', 'sleep', '300'])
                children.append(child)
                for _attempt in range(100):
                    if child.poll() is not None:
                        raise RuntimeError('Cannot create child network namespace')
                    if os.readlink(f'/proc/{child.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                        break
                    time.sleep(.01)
                else:
                    raise RuntimeError('Namespace creation timeout')
            server, client = (child.pid for child in children)

            def ns(pid, *args, **kwargs):
                return run(['nsenter', '-t', str(pid), '-n', *args], **kwargs)

            run(['ip', 'link', 'add', 'br-lab', 'type', 'bridge'])
            run(['ip', 'addr', 'add', '203.0.113.254/24', 'dev', 'br-lab'])
            run(['ip', 'addr', 'add', '198.18.0.10/32', 'dev', 'br-lab'])
            run(['ip', 'addr', 'add', '169.254.169.254/32', 'dev', 'br-lab'])
            run(['ip', 'link', 'set', 'br-lab', 'up'])
            for index, (pid, name, address) in enumerate(((server, 'ens3', '203.0.113.1/24'), (client, 'wan0', '203.0.113.2/24'))):
                outer = f'veth-{index}'
                run(['ip', 'link', 'add', outer, 'type', 'veth', 'peer', 'name', name])
                run(['ip', 'link', 'set', name, 'netns', str(pid)])
                run(['ip', 'link', 'set', outer, 'master', 'br-lab'])
                run(['ip', 'link', 'set', outer, 'up'])
                ns(pid, 'ip', 'link', 'set', 'lo', 'up')
                ns(pid, 'ip', 'addr', 'add', address, 'dev', name)
                ns(pid, 'ip', 'link', 'set', name, 'up')
                ns(pid, 'ip', 'route', 'add', 'default', 'via', '203.0.113.254')
            private_server = run(['wg', 'genkey']).stdout.strip()
            private_client = run(['wg', 'genkey']).stdout.strip()
            public_server = run(['wg', 'pubkey'], data=private_server).stdout.strip()
            public_client = run(['wg', 'pubkey'], data=private_client).stdout.strip()
            psk = run(['wg', 'genpsk']).stdout.strip()
            config = tomllib.loads((ROOT / 'config/server.example.toml').read_text())
            config['server']['endpoint'] = '203.0.113.1'
            state = {'schema_version': 1, 'config': config,
                     'server_private_key': private_server.decode(),
                     'server_public_key': public_server.decode(),
                     'peers': [{'name': 'synthetic', 'public_key': public_client.decode(),
                                'address': '10.89.0.2', 'status': 'active', 'psk': psk.decode()}]}
            fixture = base / 'fixture.json'
            fixture.write_text(json.dumps(state))
            fixture.chmod(0o600)
            bundle = base / 'bundle'
            run([ROOT / 'target/debug/examples/render_lab', fixture, bundle])
            ns(server, 'nft', '--check', '-f', str(bundle / 'server.nft'))
            ns(server, 'nft', '-f', str(bundle / 'server.nft'))
            ns(server, 'nft', '-f', str(bundle / 'server.nft'))  # owned replacement
            # wg-quick has no DNS/PostUp hooks in the generated server config.
            ns(server, 'wg-quick', 'up', str(bundle / 'wg-shadowborn.conf'))
            ns(server, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
            client_conf = base / 'client.conf'
            client_conf.write_text('[Interface]\nPrivateKey = ' + private_client.decode() +
                                   '\n[Peer]\nPublicKey = ' + public_server.decode() +
                                   '\nPresharedKey = ' + psk.decode() +
                                   '\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\n')
            client_conf.chmod(0o600)
            ns(client, 'ip', 'link', 'add', 'wg-client', 'type', 'wireguard')
            ns(client, 'wg', 'setconf', 'wg-client', str(client_conf))
            ns(client, 'ip', 'addr', 'add', '10.89.0.2/32', 'dev', 'wg-client')
            ns(client, 'ip', 'link', 'set', 'wg-client', 'up')
            ns(client, 'ip', 'route', 'add', '203.0.113.1/32', 'dev', 'wan0')
            ns(client, 'ip', 'route', 'replace', 'default', 'dev', 'wg-client')
            ns(client, 'ping', '-c', '2', '-W', '2', '198.18.0.10')
            print('PASS: real kernel WireGuard handshake, generated firewall, scoped NAT and return traffic')
            for address in ('10.89.0.1', '169.254.169.254'):
                assert ns(client, 'ping', '-c', '1', '-W', '1', address, ok=False).returncode
            ns(client, 'ip', 'addr', 'add', '10.89.0.3/32', 'dev', 'wg-client')
            assert ns(client, 'ping', '-I', '10.89.0.3', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            print('PASS: server host ICMP, metadata path and forged peer source denied')
            ns(server, 'wg', 'set', 'wg-shadowborn', 'peer', public_client.decode(), 'remove')
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            print('PASS: explicit kernel peer removal stops lab traffic (not CLI live revoke)')
            print('NOT TESTED: real Internet, DoT runtime, strict client, boot, SSH recovery, runtime no-logs')
        finally:
            for child in children:
                child.terminate()
            for child in children:
                child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        isolated()
        return
    missing = [name for name in ('unshare', 'nsenter', 'ip', 'wg', 'wg-quick', 'nft', 'ping', 'sysctl') if not shutil.which(name)]
    if missing:
        print('SKIPPED: missing lab tools: ' + ', '.join(missing))
        return
    probe = run(['unshare', '-Urn', 'true'], ok=False)
    if probe.returncode:
        print('SKIPPED: user/network namespaces unavailable')
        return
    if not (ROOT / 'target/debug/examples/render_lab').exists():
        raise RuntimeError('Build lab renderer: cargo build --locked -p shadowborn-core --example render_lab')
    environment = os.environ.copy()
    environment['SHADOWBORN_OUTER_NETNS'] = os.readlink('/proc/self/ns/net')
    result = subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside'], env=environment)
    if result.returncode:
        raise RuntimeError('Isolated namespace test failed; no host network was changed')


if __name__ == '__main__':
    main()
