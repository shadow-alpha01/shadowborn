# Fresh server installation (provisioning preview)

Target evaluation platforms: Debian and Ubuntu systemd VMs, initially x86_64.
No OS version is production-certified yet. Use a disposable owned VM and its
provider console. Do not run the network activation section on the developer
laptop. There is no automated apply/rollback implementation in this preview.

## Build and install files

On the fresh VM, install distro packages using authenticated repositories:

```bash
sudo apt-get install wireguard-tools nftables unbound ca-certificates age
cargo build --locked --release -p shadowborn-cli
./scripts/install-server.sh --dry-run
sudo ./scripts/install-server.sh
sudo install -d -m 0755 /etc/shadowborn
sudo install -m 0600 config/server.example.toml /etc/shadowborn/config.toml
sudoedit /etc/shadowborn/config.toml
shadowborn doctor
shadowborn plan --json
sudo shadowborn init
```

Replace documentation endpoint/admin addresses and WAN interface. Pin an IPv4
endpoint. Inspect all routes/subnets, UFW/firewalld/Docker/nft tables, DNS port
bindings and cloud security groups; ambiguous ownership stops this procedure.
Verify the configured SSH port and source CIDR from an independent admin session
and prove console access. Do not change sshd or remove provider agents.

Installation copies only CLI/docs, never activates services or alters the existing
client. `update-server.sh` validates installed-file ownership and retains durable
before-copies during replacement; modified files abort. An interrupted operation
leaves `pending/` for review, never silently resumes. `uninstall-server.sh` removes
only unchanged manifest-owned files and retains key/configuration state. These
package operations refuse a detected deployed gateway; see admin-recovery.md.

## Authorize a device and render

Follow client-enrollment.md for the device-generated public key. Then:

```bash
sudo shadowborn peer add --name laptop --public-key DEVICE_PUBLIC_KEY
sudo shadowborn peer list
sudo shadowborn render --output /root/shadowborn-review
sudo shadowborn client profile --name laptop --output /root/laptop.template
```

The root-only bundle contains actual secrets. Never commit it, upload it as a CI
artifact or paste it into a terminal transcript. No network is changed by render.
No reuse of an existing output directory is permitted. After changing peers,
retire all stale exports and render anew.

## Manual activation in a disposable VM

This is an operator-controlled lab recipe, not a safe remote production installer.
Take a VM snapshot with protected configuration and verify a working provider
console before changes. This fresh-VM procedure requires no existing tables named
`inet shadowborn` or `ip shadowborn_nat`, no conflicting firewall manager, and no
existing interface/config/unit with the selected name. Keep other tables intact.
If any collision exists, stop; do not flush or overwrite it.

For the default `wg-shadowborn` interface and reviewed bundle:

```bash
sudo nft list tables
sudo ip -brief address
sudo ip route show table all
sudo ip rule show
sudo ss -lntup
sudo nft --check --file /root/shadowborn-review/server.nft
sudo unbound-checkconf /root/shadowborn-review/unbound.conf

sudo install -d -m 0700 /etc/wireguard
sudo install -m 0600 /root/shadowborn-review/wg-shadowborn.conf /etc/wireguard/wg-shadowborn.conf
sudo install -m 0644 /root/shadowborn-review/server.nft /etc/shadowborn/server.nft
sudo install -m 0644 /root/shadowborn-review/unbound.conf /etc/shadowborn/unbound.conf
sudo install -m 0644 /root/shadowborn-review/shadowborn-firewall.service /etc/systemd/system/
sudo install -m 0644 /root/shadowborn-review/shadowborn-dns.service /etc/systemd/system/
sudo install -d /etc/systemd/system/wg-quick@wg-shadowborn.service.d
sudo install -m 0644 /root/shadowborn-review/wg-quick-shadowborn.conf /etc/systemd/system/wg-quick@wg-shadowborn.service.d/shadowborn.conf
sudo install -m 0644 /root/shadowborn-review/99-shadowborn.conf /etc/sysctl.d/99-shadowborn.conf
sudo sysctl -p /etc/sysctl.d/99-shadowborn.conf
sudo systemctl daemon-reload
sudo systemctl enable --now shadowborn-firewall.service
sudo systemctl enable --now wg-quick@wg-shadowborn.service
sudo systemctl enable --now shadowborn-dns.service
```

Unbound package installation may start the distro's own resolver. Inspect its
bindings: stop/disable it only if this is a dedicated fresh VM, the service is
unused and you approve that action. Never replace host resolv.conf. The dedicated
resolver runs as the package's `unbound` user and reads only its tunnel config.
If a package/AppArmor policy prevents startup, stop and record the failure; do
not disable the host sandbox globally. Validate the installed Unbound version.

Cloud firewall: explicitly permit the chosen WG UDP port; keep SSH limited to
approved administration. No public recursive DNS port is required. IPv6 egress
and IPv6 SSH/WAN bootstrap are unsupported here; use the documented IPv4 lab.
Baseline/hardened currently share the same conservative safety floor.

Test HTTPS and egress against an owned test destination from the enrolled client.
A handshake alone is insufficient. Record actual packet evidence and no-log
checks from validation.md. No throughput, production readiness or strict-client
claim follows from this recipe. For custom WG interface names, adapt the filename,
unit instance and drop-in directory consistently to the rendered name.
