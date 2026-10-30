#!/usr/bin/env python3
"""Read-only host smoke tests and an isolated file-installation lifecycle.

No privileged apply/restore/reconnect or firewall commands are executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "target/release/shadowmist"
DAEMON = ROOT / "target/release/shadowmistd"
CHECKS = 0


def run(args, codes=(0,), timeout=60):
    result = subprocess.run([str(x) for x in args], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    assert result.returncode in codes, (
        f"Unexpected exit {result.returncode} for {Path(args[0]).name}: "
        f"{result.stderr[:400]}")
    return result


def check(name):
    global CHECKS
    CHECKS += 1
    print(f"PASS {name}", flush=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-daemon", action="store_true")
    args = parser.parse_args()
    assert CLI.is_file() and DAEMON.is_file(), "Build release workspace first"
    with tempfile.TemporaryDirectory(prefix="shadowmist-smoke-") as temp:
        base = Path(temp)
        config = base / "config.toml"
        config.write_text((ROOT / "config/shadowmist.example.toml").read_text())
        cmd = [CLI, "--config", config, "--state-dir", base / "absent-state"]
        run(cmd + ["config", "validate"])
        run([CLI, "version"])
        run([CLI, "--help"])
        run([CLI, "bad-command"], codes=(3,))
        check("CLI command contract and example configuration")

        before_resolver = digest(Path("/etc/resolv.conf"))
        before_profiles = None
        if shutil.which("nmcli"):
            nm = run(["nmcli", "-t", "-f", "UUID,TYPE", "connection", "show"], codes=(0, 8, 10))
            if nm.returncode == 0:
                before_profiles = sorted(nm.stdout.splitlines())
        plan = json.loads(run(cmd + ["apply", "--dry-run", "--json"], codes=(0, 2)).stdout)
        assert not plan["changes"]
        assert not (base / "absent-state").exists()
        run(cmd + ["restore", "--dry-run", "--json"])
        assert not (base / "absent-state").exists()
        assert digest(Path("/etc/resolv.conf")) == before_resolver
        if before_profiles is not None:
            after = run(["nmcli", "-t", "-f", "UUID,TYPE", "connection", "show"])
            assert sorted(after.stdout.splitlines()) == before_profiles
        check("apply/restore dry run and offline capability probes change no profiles, resolver or state")

        for subcommand in ("doctor", "audit", "status"):
            report = json.loads(run(cmd + [subcommand, "--json"], codes=(0, 2)).stdout)
            assert report["schema_version"] == 1 and report["redacted"]
            assert not report["dns"]["enforced"]
            for interface in report["interfaces"]:
                assert interface["effective_mac"] is None and not interface["addresses"]
        check("real passive reports are valid and redacted")

        config.write_text("[identity]\nrotate_on_daemon_start=true\n")
        run(cmd + ["config", "validate"], codes=(4,))
        config.write_text("schema_version = 99\n")
        run(cmd + ["config", "validate"], codes=(4,))
        config.write_text("invalid = [\n")
        run(cmd + ["config", "validate"], codes=(3,))
        run(cmd + ["restore", "--dry-run", "--json"])
        check("invalid/future/reserved configuration fails; dry restoration remains available")

        config.write_text("schema_version=1\n[general]\nprofile='observe'\n")
        if os.geteuid() != 0:
            run(cmd + ["apply"], codes=(5,))
            assert not (base / "absent-state").exists()
            check("unprivileged mutation denied before any state write")

        once = run([DAEMON, "--config", config, "--state-dir", base / "absent-state", "--once"])
        assert json.loads(once.stdout)["state"] == "OBSERVE"
        assert not (base / "absent-state").exists()
        check("daemon one-shot inspection is read-only")

        if not args.skip_daemon:
            runtime = base / "runtime"
            daemon = subprocess.Popen([str(DAEMON), "--config", str(config),
                                       "--runtime-dir", str(runtime),
                                       "--state-dir", str(base / "daemon-state")],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 45
                while not (runtime / "status.json").exists() and time.monotonic() < deadline:
                    assert daemon.poll() is None, "daemon exited before assessment"
                    time.sleep(0.1)
                assert (runtime / "status.json").exists(), "daemon assessment timed out"
                assert stat.S_IMODE((runtime / "status.sock").stat().st_mode) == 0o660
                for request in (b"status\n", b"apply\n"):
                    with socket.socket(socket.AF_UNIX) as stream:
                        stream.settimeout(5)
                        stream.connect(str(runtime / "status.sock"))
                        stream.sendall(request)
                        payload = b""
                        while True:
                            data = stream.recv(65536)
                            if not data:
                                break
                            payload += data
                        if request == b"status\n":
                            assert json.loads(payload)["redacted"]
                        else:
                            assert payload == b""
                check("live daemon status-only socket, permissions and denied control request")
            finally:
                daemon.send_signal(signal.SIGTERM)
                output, errors = daemon.communicate(timeout=35)
                assert daemon.returncode == 0, errors[:300]
            assert not (runtime / "status.sock").exists()
            assert '"event":"stopped_persistent_settings_require_explicit_restore"' in output
            check("daemon SIGTERM cleans socket without reconnect or restore")

        # All installer effects remain inside this temporary prefix.
        stage = base / "stage"
        run([ROOT / "scripts/install.sh", "--check"])
        run([ROOT / "scripts/install.sh", "--dry-run", "--destdir", stage])
        assert not stage.exists()
        install = [ROOT / "scripts/install.sh", "--destdir", stage]
        run(install, timeout=180)
        installed_icon = stage / "usr/local/share/doc/shadowmist/assets/shadow-mist-rounded-icon.png"
        assert digest(installed_icon) == digest(ROOT / "assets/shadow-mist-rounded-icon.png")
        installed_config = digest(stage / "etc/shadowmist/config.toml")
        run(install, codes=(5,))
        run(install + ["--update"])
        assert digest(stage / "etc/shadowmist/config.toml") == installed_config
        assert list((stage / "var/lib/shadowmist/install-backups").iterdir())
        check("staged install/update backs up owned files and preserves config")

        if shutil.which("systemd-analyze"):
            # Validate original directives with executable paths pointed at this build.
            units = base / "units"
            units.mkdir()
            paths = []
            for source in (ROOT / "packaging/systemd").glob("*.service"):
                content = source.read_text().replace("/usr/local/sbin/shadowmistd", str(DAEMON))
                content = content.replace("/usr/local/bin/shadowmist", str(CLI))
                target = units / source.name
                target.write_text(content)
                paths.append(target)
            run(["systemd-analyze", "verify", "--man=no", *paths])
            check("systemd unit verification with built executables")

        uninstaller = [ROOT / "scripts/uninstall.sh", "--destdir", stage, "--keep-settings"]
        target = stage / "usr/local/bin/shadowmist"
        original = target.read_bytes()
        target.write_bytes(original + b"changed")
        run(uninstaller, codes=(5,))
        run(install + ["--update"], codes=(5,))
        assert target.exists()
        target.write_bytes(original)
        run(uninstaller)
        assert not target.exists()
        assert not installed_icon.exists()
        assert digest(stage / "etc/shadowmist/config.toml") == installed_config
        check("uninstall/update preserve modified files; clean uninstall retains config/backups")

    print(f"{CHECKS} integration checks passed; no host network mutations", flush=True)


if __name__ == "__main__":
    main()
