#!/bin/sh
set -eu
DESTDIR=
RESTORE=ask
DRY=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --destdir) shift; DESTDIR=${1:?directory required};;
        --restore) RESTORE=yes;;
        --keep-settings) RESTORE=no;;
        --dry-run) DRY=1;;
        --help|-h) echo 'Usage: uninstall.sh [--restore|--keep-settings] [--dry-run] [--destdir /path]'; exit 0;;
        *) echo 'Unknown option' >&2; exit 3;;
    esac
    shift
done
if [ -n "$DESTDIR" ]; then case "$DESTDIR" in /*) ;; *) exit 3;; esac; [ "$DESTDIR" != / ] || exit 3; fi
MANIFEST="$DESTDIR/var/lib/shadowmist/install-manifest.tsv"
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || { echo 'No owned installation manifest found; refusing removal.' >&2; exit 5; }
if [ "$DRY" = 1 ]; then
    echo 'Would stop Shadow Mist, offer restoration, and remove only unchanged manifest-owned files.'
    echo 'Configuration, recovery snapshots and install backups are retained.'
    cat "$MANIFEST"
    exit 0
fi
if [ -z "$DESTDIR" ]; then
    [ "$(id -u)" = 0 ] || { echo 'Host uninstall requires root.' >&2; exit 5; }
    if [ "$RESTORE" = ask ]; then
        printf 'Restore Shadow Mist-managed network settings before uninstalling? [Y/n] '
        read -r ANSWER
        case "$ANSWER" in n|N|no) RESTORE=no;; *) RESTORE=yes;; esac
    fi
    systemctl stop shadowmist.service
    if [ "$RESTORE" = yes ]; then /usr/local/bin/shadowmist restore; else echo 'Persistent policies and snapshots are retained; stopping is not restoration.'; fi
    systemctl disable shadowmist.service shadowmist-recover.service
fi
TAB=$(printf '\t')
CONFLICT=0
# First validate all paths and hashes; a conflict leaves the installation intact.
while IFS="$TAB" read -r EXPECTED RELATIVE; do
    case "$RELATIVE" in usr/local/bin/shadowmist|usr/local/sbin/shadowmistd|etc/systemd/system/shadowmist.service|etc/systemd/system/shadowmist-recover.service|usr/local/libexec/shadowmist/uninstall.sh|usr/local/share/doc/shadowmist/README.md|usr/local/share/doc/shadowmist/LICENSE|usr/local/share/doc/shadowmist/assets/shadow-mist-rounded-icon.png|usr/local/share/doc/shadowmist/docs/*.md|usr/local/share/doc/shadowmist/docs/project-tree.txt) ;; *) echo 'Invalid ownership path' >&2; exit 5;; esac
    case "$RELATIVE" in *..*) echo 'Invalid ownership path' >&2; exit 5;; esac
    TARGET="$DESTDIR/$RELATIVE"
    if [ -L "$TARGET" ]; then echo "Symlink conflict retained: $TARGET" >&2; CONFLICT=1; continue; fi
    if [ -f "$TARGET" ]; then
        ACTUAL=$(sha256sum "$TARGET" | cut -d ' ' -f 1)
        if [ "$ACTUAL" != "$EXPECTED" ]; then echo "Modified file retained: $TARGET" >&2; CONFLICT=1; fi
    fi
done < "$MANIFEST"
[ "$CONFLICT" = 0 ] || exit 5
while IFS="$TAB" read -r EXPECTED RELATIVE; do rm -f -- "$DESTDIR/$RELATIVE"; done < "$MANIFEST"
mv "$MANIFEST" "$MANIFEST.removed.$(date -u +%Y%m%dT%H%M%SZ).$$"
if [ -z "$DESTDIR" ]; then systemctl daemon-reload; fi
echo 'Owned installation files removed. Config, journals and backups retained in /etc/shadowmist and /var/lib/shadowmist.'
