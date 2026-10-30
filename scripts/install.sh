#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
MODE=install
PROFILE=balanced
DESTDIR=
UPDATE=0
BUILD_ONLY=0
usage() { echo 'Usage: install.sh [--check|--dry-run|--build-only] [--profile balanced|observe] [--destdir /absolute/path] [--update]'; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) MODE=check;;
        --dry-run) MODE=dry;;
        --build-only) BUILD_ONLY=1;;
        --profile) shift; PROFILE=${1:?profile required};;
        --destdir) shift; DESTDIR=${1:?directory required};;
        --update) UPDATE=1;;
        --help|-h) usage; exit 0;;
        *) usage >&2; exit 3;;
    esac
    shift
done
case "$PROFILE" in balanced|observe) ;; *) echo 'Only balanced and observe are supported; strict is phase 2.' >&2; exit 4;; esac
if [ -n "$DESTDIR" ]; then
    case "$DESTDIR" in /*) ;; *) echo '--destdir must be absolute' >&2; exit 3;; esac
    [ "$DESTDIR" != / ] || { echo 'Use no --destdir for a host installation' >&2; exit 3; }
fi
ARCH=$(uname -m)
case "$ARCH" in x86_64|aarch64) ;; *) echo "Unsupported architecture: $ARCH (audit/build at your own risk)" >&2; exit 4;; esac
if command -v apt-get >/dev/null 2>&1; then
    PREREQS='sudo apt-get install cargo rustc rustfmt rust-clippy build-essential pkg-config network-manager systemd-resolved'
elif command -v dnf >/dev/null 2>&1; then
    PREREQS='dnf detected: Fedora installation is NOT TESTED; use observe mode'
elif command -v pacman >/dev/null 2>&1; then
    PREREQS='pacman detected: Arch installation is NOT TESTED; use observe mode'
else
    PREREQS='Install stable Rust, a C linker, NetworkManager and systemd-resolved using your distribution package manager'
fi
printf 'Architecture: %s\nPrerequisite guidance: %s\n' "$ARCH" "$PREREQS"
MISSING=0
for PROGRAM in cargo rustc cc; do
    if ! command -v "$PROGRAM" >/dev/null 2>&1; then echo "Missing build prerequisite: $PROGRAM"; MISSING=1; fi
done
for PROGRAM in nmcli systemctl busctl resolvectl; do
    if ! command -v "$PROGRAM" >/dev/null 2>&1; then echo "Capability unavailable: $PROGRAM (affected features remain audit-only)"; fi
done
echo 'Installation does not enable the service, enroll profiles, apply DNS, reconnect interfaces or install dependencies.'
if [ "$MODE" = check ]; then exit "$MISSING"; fi
if [ "$MODE" = dry ]; then
    printf 'Would build two locked release binaries as an unprivileged user.\nWould install under %s/usr/local, config under %s/etc/shadowmist, and two units under %s/etc/systemd/system.\n' "$DESTDIR" "$DESTDIR" "$DESTDIR"
    echo 'Existing files require --update and ownership verification; updates preserve config and retain backups.'
    exit "$MISSING"
fi
[ "$MISSING" = 0 ] || exit 4
cd "$PROJECT_DIR"
# Cargo and build scripts must not execute as root.
if [ "$(id -u)" = 0 ]; then
    if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
        echo 'Build as an unprivileged user: ./scripts/install.sh --build-only; then sudo ./scripts/install.sh' >&2
        exit 4
    fi
    runuser -u "$SUDO_USER" -- cargo build --locked --release -p shadowmist-cli -p shadowmist-daemon
else
    cargo build --locked --release -p shadowmist-cli -p shadowmist-daemon
fi
if [ "$BUILD_ONLY" = 1 ]; then exit 0; fi
if [ -z "$DESTDIR" ]; then
    [ "$(id -u)" = 0 ] || { echo 'Build completed. Run sudo ./scripts/install.sh for final installation.' >&2; exit 5; }
    [ "$(cat /proc/1/comm)" = systemd ] || { echo 'Host installation requires systemd; use --destdir for staging.' >&2; exit 4; }
    [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ] || { echo 'Container installation is unsupported; use --destdir.' >&2; exit 4; }
    if [ -n "${WSL_DISTRO_NAME:-}" ]; then echo 'WSL installation is unsupported.' >&2; exit 4; fi
    if systemctl is-active --quiet shadowmist.service; then echo 'Stop shadowmist before updating its binaries; stopping does not restore settings.' >&2; exit 5; fi
fi
MANIFEST="$DESTDIR/var/lib/shadowmist/install-manifest.tsv"
owned_documents() {
    printf '%s\n' docs/licensing.md
    for DOC in docs/legacy/*.md; do printf '%s\n' "$DOC"; done
}
owned_files() {
    printf '%s\n' usr/local/bin/shadowmist usr/local/sbin/shadowmistd etc/systemd/system/shadowmist.service etc/systemd/system/shadowmist-recover.service usr/local/share/doc/shadowmist/README.md usr/local/share/doc/shadowmist/LICENSE usr/local/share/doc/shadowmist/assets/shadow-mist-rounded-icon.png usr/local/libexec/shadowmist/uninstall.sh
    for DOC in $(owned_documents); do printf 'usr/local/share/doc/shadowmist/%s\n' "$DOC"; done
}
if [ "$UPDATE" = 1 ] && [ -f "$MANIFEST" ]; then
    TAB=$(printf '\t')
    while IFS="$TAB" read -r EXPECTED RELATIVE; do
        case "$RELATIVE" in
            usr/local/bin/shadowmist|usr/local/sbin/shadowmistd|etc/systemd/system/shadowmist.service|etc/systemd/system/shadowmist-recover.service|usr/local/libexec/shadowmist/uninstall.sh|usr/local/share/doc/shadowmist/README.md|usr/local/share/doc/shadowmist/LICENSE|usr/local/share/doc/shadowmist/assets/shadow-mist-rounded-icon.png|usr/local/share/doc/shadowmist/docs/*.md|usr/local/share/doc/shadowmist/docs/project-tree.txt) ;;
            *) echo 'Invalid prior installation manifest' >&2; exit 5;;
        esac
        case "$RELATIVE" in *..*|*[!a-zA-Z0-9/_.-]*) echo 'Invalid prior installation path' >&2; exit 5;; esac
        TARGET="$DESTDIR/$RELATIVE"
        [ ! -L "$TARGET" ] || { echo 'Prior installation symlink conflict' >&2; exit 5; }
        if [ -e "$TARGET" ]; then
            [ -f "$TARGET" ] || { echo 'Prior installation file type conflict' >&2; exit 5; }
            ACTUAL=$(sha256sum "$TARGET" | cut -d ' ' -f 1)
            [ "$ACTUAL" = "$EXPECTED" ] || { echo 'Modified prior installation file retained' >&2; exit 5; }
        fi
    done < "$MANIFEST"
fi
for RELATIVE in $(owned_files); do
    TARGET="$DESTDIR/$RELATIVE"
    [ ! -L "$TARGET" ] || { echo "Refusing symlink target: $TARGET" >&2; exit 5; }
    if [ -e "$TARGET" ]; then
        [ "$UPDATE" = 1 ] && [ -f "$MANIFEST" ] || { echo "Existing file requires owned --update: $TARGET" >&2; exit 5; }
        EXPECTED=$(awk -F '\t' -v file="$RELATIVE" '$2 == file {print $1}' "$MANIFEST")
        CURRENT=$(sha256sum "$TARGET" | cut -d ' ' -f 1)
        [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$CURRENT" ] || { echo "Ownership/content conflict: $TARGET" >&2; exit 5; }
    fi
done
STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
BACKUP="$DESTDIR/var/lib/shadowmist/install-backups/$STAMP"
install -d -m 0700 "$DESTDIR/var/lib/shadowmist"
install -d -m 0700 "$BACKUP"
if [ -e "$MANIFEST" ]; then cp -p "$MANIFEST" "$BACKUP/install-manifest.tsv"; fi
for RELATIVE in $(owned_files); do
    if [ -f "$DESTDIR/$RELATIVE" ]; then install -D -m 0600 "$DESTDIR/$RELATIVE" "$BACKUP/$RELATIVE"; fi
done
install -D -m 0755 target/release/shadowmist "$DESTDIR/usr/local/bin/shadowmist"
install -D -m 0755 target/release/shadowmistd "$DESTDIR/usr/local/sbin/shadowmistd"
install -D -m 0644 packaging/systemd/shadowmist.service "$DESTDIR/etc/systemd/system/shadowmist.service"
install -D -m 0644 packaging/systemd/shadowmist-recover.service "$DESTDIR/etc/systemd/system/shadowmist-recover.service"
install -d -m 0755 "$DESTDIR/etc/shadowmist"
if [ ! -e "$DESTDIR/etc/shadowmist/config.toml" ]; then
    sed "s/^profile = \"balanced\"/profile = \"$PROFILE\"/" config/shadowmist.example.toml > "$BACKUP/config.new"
    install -m 0644 "$BACKUP/config.new" "$DESTDIR/etc/shadowmist/config.toml"
fi
printf '%s\n' '# Shadow Mist legacy client' '' 'See the [client guide](docs/legacy/README.md) for setup, compatibility and recovery.' > "$BACKUP/README.new"
install -D -m 0644 "$BACKUP/README.new" "$DESTDIR/usr/local/share/doc/shadowmist/README.md"
install -D -m 0644 LICENSE "$DESTDIR/usr/local/share/doc/shadowmist/LICENSE"
install -D -m 0644 assets/shadow-mist-rounded-icon.png "$DESTDIR/usr/local/share/doc/shadowmist/assets/shadow-mist-rounded-icon.png"
for DOC in $(owned_documents); do install -D -m 0644 "$DOC" "$DESTDIR/usr/local/share/doc/shadowmist/$DOC"; done
install -D -m 0755 scripts/uninstall.sh "$DESTDIR/usr/local/libexec/shadowmist/uninstall.sh"
{
    for RELATIVE in $(owned_files); do
        HASH=$(sha256sum "$DESTDIR/$RELATIVE" | cut -d ' ' -f 1)
        printf '%s\t%s\n' "$HASH" "$RELATIVE"
    done
} > "$BACKUP/manifest.new"
if [ -f "$BACKUP/install-manifest.tsv" ]; then
    awk -F '\t' 'NR == FNR { seen[$2] = 1; next } !seen[$2] { print }' "$BACKUP/manifest.new" "$BACKUP/install-manifest.tsv" > "$BACKUP/manifest.retained"
    cat "$BACKUP/manifest.retained" >> "$BACKUP/manifest.new"
fi
install -m 0600 "$BACKUP/manifest.new" "$MANIFEST"
if [ -z "$DESTDIR" ]; then systemctl daemon-reload; fi
echo 'Installed. No network configuration was applied.'
echo 'Next: sudo systemctl enable --now shadowmist-recover shadowmist; shadowmist doctor'
