# Debian / Kali packaging

Use `scripts/install.sh` for the MVP; it builds locked release binaries as the
unprivileged invoking user and installs only after that build. A staged tree is
available through `--destdir` for package review. No `.deb` is claimed or
published. Native maintainer scripts/package upgrades remain future work, after
the isolated Kali integration gates. No network configuration is applied by
installation or package registration.
