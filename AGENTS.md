# AGENTS.md — SHADOWBORN

> **Authoritative implementation contract for Codex — 2026-10-30.**
> Repository: `https://github.com/shadow-alpha01/shadowborn` (already renamed on GitHub from `shadow-mist`).
> Product: **Shadowborn**, a hardened, self-hosted, high-performance WireGuard full-tunnel Internet gateway with standard WireGuard clients. Preserve existing working **Shadow Mist** functionality instead of silently turning an installed client into a server.
> This document defines engineering targets and RELEASE GATES, not claims about features already shipped. Inspect the current tree before coding.

**Owner's unambiguous desired behavior:** deploy a small Shadowborn server on an owned VPS (initial VM testing in Germany, later portable across providers/countries), securely authorize a laptop with per-device keys, activate a persistent standard WireGuard connection, route Internet traffic through the VPS, and egress from the VPS IP. In the **strict** Linux-client profile, traffic that would bypass the VPN must be denied by host firewall policy even during boot, sleep, network changes, tunnel loss or server outage. Provide a high-performance configuration and no retained *activity history* in Shadowborn-owned services. Never claim that external ISP, VPS provider, OS, web sites or upstream resolvers are unable to retain their own metadata. Security does not require pretending that a VPN makes the user anonymous.

## 0. MISSION, AUTHORITY, AND NON-NEGOTIABLES

**Deliverable:** transform/extend the present repository into `shadowborn`: an auditable Rust-based management and provisioning tool for a hardened Linux WireGuard gateway. The server receives encrypted traffic from individually authorized devices, routes it to the Internet, and returns replies through the tunnel. Client devices can use standard Linux kernel WireGuard, `wg-quick`, and `systemd`; **do not require a custom client daemon**. Provide optional minimal client-side `nftables` fail-closed integration, because a server alone cannot prevent client-side leaks.

**Security goals (in priority order):** (1) no unintended direct client egress in strict mode, including during boot and tunnel failure; (2) correct authenticated keying and access revocation; (3) strict no-retained-activity-logs policy; (4) isolation of the server and its peers; (5) useful Internet performance; (6) reversible administration with current-state diagnostics, not historical usage logs. Prefer boring, well-reviewed Linux facilities over inventive crypto, obfuscation or multiple nested transports.

**Honest guarantees:** WireGuard encrypts client-to-server tunnel traffic, NOT the entire end-to-end Internet route. The ISP sees client-to-VPS encrypted packets, destination VPS IP, timing and sizes; the VPS provider sees the gateway's outgoing destinations/metadata, and the destination receives the VPS public IP. HTTPS protects application content independently. The VPN server must NOT claim to render traffic anonymous, untraceable, unbreakable or post-quantum-secure. No userland kill switch guarantees complete secrecy from privileged malware, kernel compromise, firmware, layer-2 identifiers or malicious endpoints. Show explicit protection scopes and fail/unknown states.

**Change authority:** do NOT rename a GitHub repository, change remotes, alter an existing live host's routes/firewall, delete data, rotate production keys, switch a running client's DNS, apply NAT or open server ports without explicit operator approval. Build, dry-run, lint, unit tests and isolated network namespaces are authorized by default. No `curl | sh`. No committing passwords, keys, PSKs, credentials, generated client profiles or operational IP inventories. Do not auto-deploy to the developer's existing Kali laptop or change its working `shadowmist` DoT state.

**Repository renaming:** the GitHub path `shadow-alpha01/shadowborn` is already live, but current `README.md`, `Cargo.toml` and package paths still show Shadow Mist naming. Update user-facing server names, docs, installation/packaging, service names and CLI consistently. Do not change `origin` or rename the repository remotely. Preserve old `shadowmist` command/service compatibility, do NOT uninstall/overwrite the existing Kali host application and do NOT silently remove legacy crates; provide a documented server/client split. If developer's local remote still points at old URL, document (do not execute) `git remote set-url origin git@github.com:shadow-alpha01/shadowborn.git`.

## 0A. STRICT NO-ACTIVITY-LOGS POLICY — MANDATORY RELEASE GATE

**Owner requirement: Shadowborn must not retain usage or network-activity logs. This is a product-level, default-on, non-optional rule, not merely a UI preference.** Do not confuse this with a guarantee of global anonymity or zero trace on all infrastructure.

- **Never create or persist:** DNS query history; requested domain names; browsed URLs; destination IP/port flow histories; packet captures; payload contents; connection/session histories; per-peer traffic history; handshake/event timelines; source public IP histories; client geolocation, access logs or identifiable usage analytics. No account/activity database, request tracing, telemetry, crash reporting, analytics SDK, remote collector, syslog forwarding, Prometheus exporter or hidden debug log. Avoid collecting these fields in the first place.
- **No log output from Shadowborn services in normal operation.** The Rust server controller and bundled DNS services must not write activity to files, syslog, journald, stdout/stderr (when run as system services) or a remote endpoint. Do not configure `nftables` `log`/`nflog`, WireGuard debug tracing or DNS query logs. For Shadowborn-owned systemd units, use appropriately tested service-level suppression such as `StandardOutput=null` / `StandardError=null` and prevent internal logging sinks; CLI responses to an interactive operator may show **current, narrowly scoped** health and error status only, redacted and without a stored history. Suppress query/access/connection logs in Unbound and any future Pi-hole/dnscrypt-proxy integration; verify the exact daemon settings against their installed versions. A status probe must never write a DNS query or peer IP to persistent logs.
- **Never persist counters/handshakes:** `wg show` and in-kernel WireGuard/conntrack may hold live handshakes, peer endpoints, counters and connection state in RAM for operation. On-demand, privileged `status` can read live state without caching, exporting, saving, emitting background events or building time series. Do not schedule periodic recording of these values. Store only indispensable **configuration/security state**, such as authorized peer public keys and assigned tunnel addresses, revocation state, protected private keys/PSKs, and atomic rollback snapshots. These are necessary for the VPN to work and **are not activity logs**; minimize their fields, permissions, retention and copies. Do not store peer creation time unless essential to a documented non-activity function.
- **No persistent troubleshooting mode in v1.** Troubleshooting should use explicit on-demand diagnostics with ephemeral in-memory state, minimal redacted output and no automatic storage. Never turn on packet capture, verbose DNS query logging or persistent trace collection automatically, even after failures. Tests may create synthetic diagnostics **only in disposable isolated VMs/namespaces** using invented addresses/domains; never use live customer browsing/peer data in fixtures or CI artifacts.
- **No-log verification is required:** add automated tests asserting no Shadowborn-owned activity log files, no query/access logging options, no `nft` logging rules, no telemetry/remote exports, and no persisted per-peer handshake/traffic history after ordinary use, service restarts, tunnel failure, DNS failure, client revoke and reboot. Inspect service/journal interactions and documented dependency defaults, and repeat with the future Pi-hole stack. Mark unverified components as `UNKNOWN`, not compliant.
- **Transparency and OS boundary:** Do NOT promise that *nothing anywhere* is logged. The host OS, `systemd` manager, kernel, SSH, cloud/VPS provider, upstream DNS provider, websites and network operators may retain their own records; some records are legally mandated or necessary for incident response. Shadowborn must never silently disable the host's global security/audit logs or claim to control a hosting provider's records. Publish a precise `docs/no-logs-policy.md` identifying what Shadowborn never collects, the minimal secrets/configuration it necessarily stores, which system and provider records are outside its control, and the operational/security tradeoffs. If zero records throughout the entire host/provider is requested, explicitly report that this cannot be guaranteed.

**Release gate:** a build with saved DNS lookups, browsed sites, connection histories, packet captures, peer activity logs or telemetry FAILS even if the VPN otherwise works. Make default config and tests reflect this policy; do not add a `query_logging=true` option.

## 0B. VERIFIED PROJECT BASELINE AT AUTHORING TIME

The public GitHub repo now resolves as `shadow-alpha01/shadowborn`; the currently visible workspace lists four `shadowmist-*` crates, Rust edition 2021, rust-version 1.85 and a workspace MIT license declaration, with an AGPL-3.0 repo license. README remains titled `ShadowMist` and describes the existing **non-VPN** local privacy monitor. These are **observed baseline facts**, not assumptions that a Shadowborn server already exists. Re-read the checkout and `git status` because newer commits may supersede them. Do not claim completed tests or working server-side tunneling based on the old client results.

**Identity of the two products:** `shadowmist` = established local host privacy/audit/DoT/MAC tooling; `shadowborn` = new independent self-hosted WireGuard server + optional Linux-client lockdown helper. They MAY coexist on a Linux laptop, but no service or configuration mutation may be silently shared. The owner prefers one repository during migration; modular workspace separation and independent packages are required.

**Naming contract:** public project `Shadowborn`; repo `shadowborn`; server admin CLI `shadowborn`; server interface `wg-shadowborn` (configurable); standard tunnel unit `wg-quick@wg-shadowborn.service`; no obligation to install a custom client daemon; project-owned DNS service (e.g. `shadowborn-dns.service`) only when it actually exists. Keep backwards compatibility for `shadowmist` users, and document any later deprecation.

## 1. FIRST INSPECT THE EXISTING PROJECT — DO NOT START OVER

Before editing, inspect these actual repository paths:

- `Cargo.toml`, `Cargo.lock`: Rust workspace, Rust 2021, currently crates `shadowmist-core`, `shadowmist-platform-linux`, `shadowmist-daemon`, `shadowmist-cli`.
- `README.md` and `docs/` especially `docs/validation.md`, `docs/recovery.md`, `docs/README.pl.md`.
- `scripts/install.sh`, `packaging/systemd/`, `config/shadowmist.example.toml`, `tests/` and `.github/workflows/`.
- Existing safe network change journals, planning/compare-before-write, D-Bus integration, DNS probe/status logic and integration tests.

**Existing host functionality matters.** The legacy `shadowmist` application already controls local NetworkManager MAC/DoT/IPv6 policy; the owner has confirmed a functioning DoT/Quad9 setup on Kali, and persistent settings may exist. Do not silently repurpose that binary or remove its configs. Preserve it in version control and either (a) keep its workspace packages and installer explicitly labeled `legacy-client`, excluded from *server* installation, or (b) make a documented, reversible split with a release/branch/tag and migration path. Prefer (a) for now. New server code must never import desktop NetworkManager assumptions into the server runtime.

**Detected licensing inconsistency:** GitHub shows the repository as AGPL-3.0, while the current `[workspace.package] license` still says MIT; verify `LICENSE` and README at coding time. Audit origin, ownership, and any copyright constraints. Do not unilaterally relicense third-party/older code. Align metadata to the genuine applicable license with a short `docs/licensing.md`, preserving third-party notices and license obligations. AGPL-3.0-only may be appropriate **only when authorized and legally applicable**.

Record baseline `git status`, actual file tree and existing tests. Do not alter uncommitted changes. Provide a migration plan in `docs/migration.md` before structural edits.

## 2. TARGET ARCHITECTURE

```text
       [Linux laptop / standard WireGuard client]
       [nftables persistent STRICT kill switch]
       [wg-shadowborn via wg-quick@wg-shadowborn.service]
                 || full tunnel: IPv4 and IPv6 ||
                 || authenticated WireGuard UDP  ||
                 vv
      PUBLIC INTERNET / UNTRUSTED NETWORK
                 || encrypted outer UDP packets ||
                 vv
    +-----------------------------------------+
    | owned Linux VPS / dedicated server      |
    | public UDP WG endpoint + key validation |
    | wg-shadowborn (kernel WireGuard)                |
    | nftables INPUT/FORWARD/NAT             |
    | per-peer ACL + source address checks   |
    | VPN-scoped validating DNS resolver     |
    | Rust shadowborn CLI/controller  |
    | systemd managed + crash recovery       |
    +-----------------------------------------+
                 || SNAT/routed egress         ||
                 vv
           INTERNET DESTINATIONS
```

Control-plane vs data-plane MUST remain separate:

- **Data-plane:** in-kernel WireGuard (`wireguard-tools`, kernel support), standard Linux routing, `nftables`, `conntrack`, `systemd-resolved`/Unbound where suitable. Never proxy packet payloads through Rust merely to call it a VPN; avoid custom TUN/TAP and homebrew crypto.
- **Control-plane:** Rust-based `shadowborn` CLI plus optional limited local-only health controller. Manage peers/config/keys, live status, policy validation, backup/recovery and integration; never retain an activity audit trail. **No remotely exposed HTTP dashboard or public enrollment API in v1.** Control via local root CLI / admin SSH.
- **Client data-plane:** `wg-quick@wg-shadowborn.service` and standard `.conf`. A minimal installer for persistent client firewall policy is allowed. No Rust client required for v1.
- **Server OS initial targets:** modern Debian and Ubuntu LTS (explicitly tested versions only); support x86_64 and aarch64. Client: Linux with WireGuard + systemd/nftables; other WG clients supported as `best effort` without a Linux kill-switch guarantee.
- **Infrastructure:** single VPS, one WireGuard interface `wg-shadowborn` (or documented, configurable name), one UDP listening port, named peers, one IPv4 tunnel prefix and optional IPv6 tunnel prefix. No requirement for Docker, Kubernetes or centralized databases.

## 3. CRYPTOGRAPHY, PEER IDENTITY AND ENROLLMENT

WireGuard's standard Noise-based protocol, Curve25519, ChaCha20-Poly1305 and BLAKE2s are non-negotiable. Do not implement crypto primitives or handshakes yourself. Prefer the kernel implementation for performance. Kernel WireGuard already rekeys sessions: do not invent overlapping ad-hoc key rotation or duplicate TLS wrapping for the same threat model.

- One distinct cryptographically random WireGuard keypair **per device**; never share device private keys. One server keypair per server interface, plus a **per-peer preshared key (PSK)** by default when it can be provisioned safely. PSK is an optional extra secrecy input; do not promise full post-quantum security.
- **Preferred enrollment (zero client-private-key exposure on server):** the device generates its own private/public WG keys, provides only its public key to the admin over authenticated SSH or offline means. Server creates a peer with a unique `/32` IPv4 tunnel address and `/128` IPv6 tunnel address if available, associates per-peer PSK, and emits a client config template or secure pairing bundle. Securely deliver PSK out-of-band; never show it in routine logs.
- **Optional convenience flow requested by owner:** `shadowborn peer issue --name LAPTOP --bundle ...` generates a single-device importable `.conf` on the server. Explicitly warn that this method creates the client private key on the server; create only with user opt-in and protect as an ephemeral secret. Output must be encrypted to an operator-supplied recipient key (e.g. age) or to a user-provided encrypted removable medium; alternatively allow a one-time root-only `0600` artifact that expires and is securely removed as well as practicable (do NOT claim secure file erasure on SSD). Never print keys to console in CI, URL, QR/web interface, logs, shell traces or Git.
- Provisioning is ADMINISTRATOR-AUTHORIZED; merely possessing a shareable token is not equivalent to peer authorization. No automatically approving public registration in v1. If a later one-time invitation protocol is added, use strong entropy, single use, short expiry, verified server identity, rate limits and an auditable state machine; NEVER treat a reusable shared master password as peer identity.
- Maintain per-peer states: `active`, `disabled`, `revoked`; unique IDs and names, but no connection or activity timestamps. Avoid unnecessary enrollment timestamps. Disallow duplicate public keys and overlapping `AllowedIPs`. `peer revoke` removes the peer live via WG control plane and persists atomically; revocation must not leave a stale allowed peer on restart. A compromised client secret requires issuing fresh client credentials; do not promise retroactive recovery.
- Rotate server keys only through explicitly requested maintenance, with migration guidance. Never silently reset every client.
- Permission boundaries: `/etc/wireguard` and secret state root-owned `0700` directories / `0600` files; root-only control-plane writes; secure temp files and atomically replace configuration. Use restrictive umask and redact logs/error traces.
- Include `peer list`, `peer add --public-key`, `peer issue`, `peer disable`, `peer revoke`, `peer rotate-psk`, `peer export-public`, `peer show --redacted`, and a secure enrollment guide with examples that contain placeholders, **not generated real credentials**.

## 4. WIREGUARD SERVER, ROUTING, AND EGRESS

- Use one well-documented configurable UDP port (default `51820/udp`); do not make port-hopping or covert DNS-tunneling a security feature. Expose **only** WireGuard UDP plus tightly controlled SSH (ideally admin allowlisted) by default.
- Client profile MUST support full tunnel: `AllowedIPs = 0.0.0.0/0, ::/0` when IPv6 egress is functional. Use an explicit server endpoint IP by default to avoid insecure DNS bootstrap; support hostname only with documented, secure endpoint resolution and controlled exception updates.
- Server peer config MUST constrain `AllowedIPs` for EACH client to that client's individual tunnel source address(es), NOT `0.0.0.0/0` on the server. Prevent client source spoofing and peer-to-peer by default using both WG and firewall checks.
- Inbound forwarding only from `wg-shadowborn` to the expressly selected Internet egress interface, with stateful return path. Never expose host management, Docker bridges, private cloud metadata endpoints, RFC1918/ULA/link-local networks or other clients to tunnel peers without an explicit policy and test. Prevent access to VPS/cloud metadata addresses (e.g. `169.254.169.254`) from peers.
- IPv4 egress: correctly implement sysctl forwarding and `nftables` SNAT/masquerade on **only** intended traffic/egress interface. No blanket NAT or `iptables -F`. `FORWARD` deny-by-default for client flows, allow established/related return traffic, validate interfaces/source subnets. Preserve other system tables and rule ownership.
- IPv6: support proper routed IPv6 prefix where the host/provider supplies one; avoid NAT66 if a routed prefix is available. If not supported, mark IPv6 `BLOCKED` and **block physical-client IPv6 egress** in strict mode; NEVER silently permit IPv6 to escape outside the tunnel. Document an IPv4-only guarded mode and a dual-stack verified mode.
- Routing/policy/MTU: use standard `wg-quick` and route rules; avoid hardcoded egress name (`eth0` is not universal). Detect valid default WAN interface, NAT and cloud provider firewall requirements. Default MTU via verified path behavior, with documented per-host overrides and PMTUD tests. MSS clamping only if a real problem is demonstrated, not always-on cargo-cult tweaking.
- Enable reasonable NAT keepalive (`PersistentKeepalive = 25` only for clients behind NAT needing it). Graceful reconfiguration should prefer `wg syncconf` when safe over taking the interface down. Set persistent `systemd` startup/restart units, sane timeouts and idempotent operations.

## 5. CLIENT FAIL-CLOSED KILL SWITCH — CRITICAL REQUIREMENT

**The server cannot enforce this on the laptop; supply separate optional Linux `shadowborn-client-lockdown` systemd + nftables integration for strict clients.** No custom VPN app needed. No setting claims a leak-free client unless the lockdown is actually active and verified.

- Implement as persistently installed `nftables` policy before VPN activation, never a fragile `PostUp`-only rule that disappears on `wg-quick down`, crash or reboot. The default application egress path must be DROP/REJECT when tunnel is absent; allow encrypted WireGuard **outer** packets only to explicitly trusted endpoint IP:UDP port and essential minimum local-link control traffic needed to acquire/retain connectivity (e.g. DHCP/ARP/NDP). Examine mark/fwmark and nft hook behavior to avoid infinite routing loops or permissive `-o physical` rules. Local link traffic itself is not encrypted by WG; be honest about that boundary.
- Cover IPv4 AND IPv6, multiple interfaces (Wi-Fi, Ethernet, tethering), network switches, sleep/wake, reboot, DNS changes, alternate routes, policy routing, VPN restart, route loss and roaming. Block external cleartext DNS on any physical interface; catch both TCP/UDP 53. Note HTTPS/DoH/QUIC inside the tunnel is fine; do not blanket-block 443 or unrelated web traffic.
- Enforce lock-down even with no `wg-shadowborn` interface. For strict full-tunnel mode, only the WireGuard outer UDP endpoint is permitted to leave physically; **do not** allow all traffic on port 51820 to arbitrary IPs, general RFC1918 LAN traffic or arbitrary exceptions. Provide separate explicit temporary captive-portal/LAN access mode with timeboxed rollback and conspicuous `NOT STRICT` display; no silent bypass.
- No reliance on running a long-lived daemon for the firewall to stay enforced. Maintain explicit, persistent and atomic nft table ownership. Avoid clearing external rules, disabling existing firewalls or breaking Docker rules. Include conflict detection and `nft -c` validation before apply.
- Remote SSH safety: never enable/change client kill switch on a remote workstation without explicit confirmation. Provide staged plan, rollback timer, recovery via physical console and `lockdown status/enable/disable --confirm` with clear warnings. In strict mode, an outage must result in **loss of Internet**, not bypassing the tunnel. This is intentional and conflicts with uninterrupted connectivity.
- DNS resolver/routing loops: prefer sending VPN-scoped DNS to server's tunnel IP; ensure local resolver cannot choose an untunneled upstream. `systemd-resolved`, NetworkManager and legacy Shadow Mist DoT integration must be detected, not overwritten silently. WireGuard client config includes DNS setting where supported; document resolvconf dependency.
- Explicitly warn that PF_PACKET/DHCP/link-layer traffic may bypass normal IP firewall hooks; test what can and cannot be blocked. `VERIFIED` claims require scoped tests, never absolute guarantees.

## 6. DNS PRIVACY, RESOLUTION, AND POLICY

- Recommended: a lightweight server-side resolver bound ONLY to the WG interface/tunnel addresses, e.g. Unbound validating DNSSEC where possible, with configurable upstream Quad9 DNS-over-TLS. This means client-to-server DNS is inside encrypted WireGuard and server-to-upstream DNS is encrypted DoT. **Do not** rely on the client reaching Quad9 directly outside the VPN.
- Do not expose the server as an open recursive resolver on its public Internet interface. DNS access limited by interface/peer ACL. Make client-side server DNS mandatory in `strict` profile unless user explicitly chooses a different in-tunnel policy.
- Support clean DNS failure rather than silent cleartext fallback. Handle startup and resolver outage without leaking to system/router DNS. Avoid lying about application-local DoH and independent resolver choices; all application IP packets must still go through VPN if the kill switch is effective.
- Optional later: privacy-preserving blocklists, configurable upstreams, local split-DNS with explicit peer policy. DNS query logging is always OFF and unavailable as a user option in v1. Don't load extra stacks (Pi-hole, dnscrypt-proxy, Prometheus, Wazuh) in v1 without need.
- Document who learns what: ISP sees VPS IP and timing; VPS operator sees connection metadata and egress destinations; chosen upstream recursive DNS resolver learns requested names if used; visited sites see server public IP.

## 7. SERVER HOST HARDENING

- SSH keys only as the desired end state, not an automatic destructive switch: **verify an alternate working admin key/session first**, then offer guarded steps to disable password/root login. Preserve emergency host console access and existing admin allowlists. Firewall updates require a pre-armed rollback timer or out-of-band console; an interrupted SSH session must not permanently lock out the operator.
- `nftables` default-deny inbound and forwarded services with explicit exceptions; least privilege per interface and peer. `nft` rules as owned table(s) and idempotent fragments, never wholesale flush. Check UFW/firewalld/Docker/iptables-nft conflicts and explicitly refuse unsafe overlaps.
- Firewall interface/port/route/provider detection and backups before apply. Sysctl minimal and documented (IP forwarding needed); never blindly disable reverse path filtering/security knobs without proving a routing need.
- Minimal Rust control-plane attack surface: CLI first, no network listener, optional read-only monitor without root privileges; privileged operations in short-lived root CLI, safe command invocation **without shell interpolation**. Validate peer names, IPs, ports and paths. Protect state from symlink/path traversal and TOCTOU; atomic file writes/fsync/locks as appropriate. No telemetry, ever, in v1; no activity logging by default or on service failure.
- Service units use appropriate `NoNewPrivileges`, `ProtectSystem`, restricted read/write paths, capabilities only where genuinely needed, sandbox compatible with `wg` and `nft`. Don't strip `CAP_NET_ADMIN` from a component that actually must administer interfaces. Harden systemd units and validate with `systemd-analyze security` where meaningful.
- Keep packages pinned/locked (`Cargo.lock`), check CVEs, validate signatures/hashes for releases, record SBOM/dependency provenance where feasible, CI with dependency auditing. No automatic unreviewed kernel/network stack modifications.
- Isolate clients from each other by default. Do not create client activity logs or retain connection metadata. Rate-limit administrative authentication where appropriate using existing host facilities without adding VPN usage records. Assess the **current** handshake and service condition on demand without saving history. Never store browsing history.

## 8. RELIABILITY, ROLLBACK, AND SERVICE SEMANTICS

- Support `systemctl enable --now wg-quick@wg-shadowborn`, `systemctl restart wg-quick@wg-shadowborn`, plus clear optional `shadowborn` status/monitor units. Document that stopping the monitoring process must **not** automatically tear down WireGuard; stopping the WG unit explicitly tears down the tunnel. Do not misleadingly conflate monitor status with tunnel/egress health.
- Expose `shadowborn init`, `doctor`, `plan`, `apply --confirm`, `status`, `peer ...`, `firewall ...`, `dns ...`, `backup`, `restore`, `validate`, `uninstall --plan`, `version`. Implement these progressively; unsupported commands must fail clearly, never fake success.
- Preflight shows exact network changes, open ports, current SSH exposure, WAN interface, public addressing, IPv6 readiness, tunnel prefix collisions, DNS port conflicts, kernel WG support, nftables conflicts and cloud firewall obligations. `plan` and `--dry-run` do not mutate host.
- Transactional apply: take protected backup and baseline; check current value before writing; write config atomically; validate `wg-quick`/nft syntax, stage independent timed rollback; activate, probe routing/DNS/handshake only with a real opted-in test peer; commit after validation. Crash/reboot recovery leaves system in known state and does not destroy other admins' rules. Restore only settings owned by this project, detect conflicts.
- Server maintenance must be safe over SSH. Provide operator-supplied out-of-band access check, never assume remote console available. Snapshot/backup and disaster recovery docs; restore must never accidentally resurrect revoked peers.
- Per-client idempotent revoke and durable persistence: client removed from kernel and config; daemon restart and host reboot cannot reauthorize a revoked key. Key rotation and peer address change require explicit confirmation and a staged migration.
- On-demand, nonpersistent diagnostics: `wg show` latest handshake, live RX/TX counts, server DNS health, egress test, firewall state, egress IP, UDP reachable (from an actual external test peer), IPv6 status, endpoint changes; current warnings for stale sessions, blocked MTU path, open recursion, LAN exposure, firewall bypass. Never log or archive any of these values or client identities. Do not treat a handshake alone as proof of Internet access or leak protection.

## 9. PERFORMANCE WITHOUT REDUCING SECURITY

- Baseline: kernel WG, nftables and host network stack; avoid user-space packet relays and nested VPN/DoT tunnels when they have no practical benefit. For typical consumer/high-throughput VPS, use one interface and lean services.
- Benchmark direct and tunneled throughput/latency with `iperf3` and/or equivalent controlled tests, multiple TCP streams, UDP loss/jitter, CPU usage, NAT conntrack saturation, handshake/reconnect latency, DNS p50/p95. Record kernel version, VPS type, server NIC, MTU and test topology. No made-up throughput claims.
- Optimize measured bottlenecks only: CPU, cryptographic performance, provider bandwidth, UDP filtering, path MTU, nft conntrack, queueing. Optional BBR/fq/MTU/MSS/rmem tuning is **off by default** and requires comparative results + rollback.
- Support network switching, suspend/resume, NAT mapping churn and mobile clients where standard WireGuard permits. Clearly label that strict fail-closed may block traffic during these events until the tunnel recovers.
- Do not use multilayer cryptography, VPN-over-DNS, obfuscation, port rotation, randomized transport or payload padding by default: each adds complexity, possibly leakage and performance overhead, and is not required for a robust WireGuard gateway.

## 10. PROJECT LAYOUT (ADAPT, DO NOT BLINDLY REPLACE)

Target shape; keep existing tested crates unless moved with a documented migration:

```text
AGENTS.md
Cargo.toml
Cargo.lock
LICENSE
README.md
crates/
  shadowmist-core/                # existing shared data validation and safety helpers
  shadowmist-platform-linux/      # existing host integration where reusable
  shadowmist-daemon/              # legacy client (no server install)
  shadowmist-cli/                 # legacy client (no server install)
  shadowborn-core/         # new: peer model, policy, planner, state, config
  shadowborn-platform/     # new: Linux wg/nft/sysctl/DNS adapters
  shadowborn-cli/          # new: main server CLI
config/
  server.example.toml
  unbound/                        # secure examples, no secrets
packaging/
  systemd/                        # server WG + monitor + recovery templates
  nftables/                       # server and client-owned rulesets/templates
scripts/
  install-server.sh
  update-server.sh
  uninstall-server.sh
  install-client-lockdown.sh      # optional, minimal, Linux only
  validate.sh
tests/
  unit/
  integration/
  namespaces/                     # isolated Linux netns / veth tests
  vm/                             # dangerous live tests only in disposable VMs
docs/
  architecture.md
  threat-model.md
  migration.md
  installation-server.md
  client-enrollment.md
  client-kill-switch.md
  dns-privacy.md
  no-logs-policy.md
  security-hardening.md
  admin-recovery.md
  validation.md
  performance.md
  licensing.md
  reference-mistborn.md
assets/                             # preserve existing repo artwork
```

`shadowborn` may be a Rust binary exposing all the administrative commands; name the systemd tunnel `wg-quick@wg-shadowborn.service`. If providing `shadowborn.service`, make it a monitoring/controller service with accurately documented lifecycle, not a replacement for WireGuard itself. No WebUI in v1.

## 11. CONFIGURATION MODEL AND SAMPLE CLIENT

Use versioned TOML with strict validation and explicit profiles, typed fields, no arbitrary shell commands, unknown-key warnings/errors, and no secret values in generated example configs:

```toml
schema_version = 1
[server]
interface = "wg-shadowborn"
listen_port = 51820
endpoint = "REPLACE_WITH_SERVER_PUBLIC_IP"
tunnel_ipv4 = "10.89.0.1/24"
# tunnel_ipv6 = "fd89:89::1/64"   # only when IPv6 path handling is tested
wan_interface = "auto-detect"    # must require review before applying

[security]
peer_isolation = true
restrict_peer_lan_access = true
psk_per_peer = true
public_management_api = false
firewall_default_deny = true

[dns]
mode = "vpn-resolver"
bind_to_vpn_only = true
upstream = "quad9-dot"
query_logging = false  # fixed; cannot be enabled; no query/history logging

[privacy]
no_activity_logs = true  # mandatory, cannot be disabled
telemetry = false         # mandatory, cannot be enabled
store_peer_activity = false

[operations]
auto_apply_on_install = false
require_confirm = true
transactional_rollback = true
```

Example **template**, NOT a credential that would work without personalization:

```ini
[Interface]
Address = 10.89.0.2/32
PrivateKey = <DEVICE_PRIVATE_KEY_NOT_STORED_IN_GIT>
DNS = 10.89.0.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
PresharedKey = <UNIQUE_PEER_PSK>
Endpoint = <SERVER_PUBLIC_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

If there is no tested server IPv6 egress, still route or block all IPv6 in the **client firewall**; document clearly that IPv6 Internet access is intentionally unavailable until correctly supported. Test actual `wg-quick`, `resolvconf` and client firewall behavior instead of assuming this template works unchanged on every distro.

## 12. SECURITY TEST PLAN — THIS IS A RELEASE GATE

At minimum automate and document realistic tests. Treat source review / simulation separately from actual network traffic evidence:

1. **Local CI and code safety:** `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace`, `cargo build --locked --release --workspace`, shellcheck, unit validation of systemd/nft syntax, secret scans, dependency audit; include deterministic mock adapters for failure paths.
2. **Network namespace integration:** namespaces representing client, Internet, gateway, DNS and destination; veth routing, WG handshakes, NAT, source spoof attempts, peer isolation, blocked public management services, DNS ACL, IPv4/IPv6 behavior. If WG kernel support unavailable in CI, mark SKIPPED accurately and run in supported Linux VM.
3. **DNS leaks:** packet capture physical client interfaces and server WAN; only encrypted WG outer UDP from client (besides explicit L2/link-control), no plaintext DNS on physical interface, client resolver cannot silently revert to DHCP DNS, server upstream DoT authenticated. Include browser/application-owned DNS but do not claim it is fully enforceable without inspection.
4. **Kill-switch failures:** no tunnel, wrong PSK/private key, unknown peer, WG process crash, server reboot, DNS outage, change WLAN -> Ethernet, device suspend/resume, IPv6-only network, server endpoint IP change, active firewall reload, `wg-quick down`, loss of routes, daemon killed with SIGKILL, restart before/after networking. Fail closed without unintended Internet egress.
5. **Server firewall:** arbitrary ingress except WG/admin rejected; VPN peer must not access SSH/metadata/Docker/host LAN/other peers by default; DNS only within WG; invalid source IP blocked; conntrack allows established replies; reboot persists policies; no flushing third-party rules.
6. **Peer lifecycle:** parallel enrollment race, duplicate names/key rejection, injection attempts, permission denial, insecure filesystem, revoke immediate + after reboot + after failed transaction, PSK rotation, client key theft exercise, backup restore cannot revive revoked peers unnoticed.
7. **Remote admin safety:** staged firewall update over SSH, out-of-band rescue, rollback on interrupted apply, idempotent update and uninstall, verified preservation of unrelated existing host network config.
8. **No-logs behavior:** validate that neither the Shadowborn server, its DNS resolver, nftables policy nor project-owned systemd units retain DNS queries, traffic/connection histories, packet payloads, peer activity, telemetry or crash logs after successful operations and failures; check service and dependency configuration. Do not mistake OS/provider logs for Shadowborn-owned logs.
9. **Internet correctness and performance:** real HTTPS website reachability and `curl -4/-6` egress IP matching expected server egress, DNS lookup, MTU path test, throughput/latency compared to direct, packet loss under stress, performance on x86_64 and aarch64 when available. No DoS against third parties; tests on owned infrastructure only.
10. **Independent external observation:** authorized tcpdump on client's physical NIC and server's external/WG NIC. A proper `VERIFIED` label must identify which interface, time window, IPv4/IPv6, DNS and destinations were actually checked. `NOT_TESTED` if impossible.
11. **Client supported configurations:** desktop Kali with NetworkManager+`systemd-resolved`, Debian and Ubuntu; record conflicts with existing `shadowmist` local DoT, Docker bridges, corporate VPN, split DNS, hostname-based endpoints, captive portal.

Maintain a checklist `docs/validation.md` with `PASS / FAIL / SKIPPED / NOT TESTED`, evidence, environment and rollback steps. NEVER check off tests solely on the basis of writing a test script. A green fake status is a security bug.

## 13. ITERATIVE DELIVERY PHASES — CODEX MUST EXECUTE, NOT JUST DESIGN

**Phase 0 — discovery and design (mandatory first):** inspect actual repo and local changes; inventory existing code; write `docs/threat-model.md` (adversaries: ISP, hostile LAN/AP, VPS provider, external attacker, compromised peer, lost laptop, admin error); write architecture, baseline validation and migration plan. Address GPL/AGPL metadata mismatch without assuming permission to relicense. No host changes.

**Phase 1 — working server MVP:** Rust server CLI, validated configuration, key handling, peer add/list/revoke/disable, `wg-shadowborn` configuration generation, minimal server `nftables` NAT/firewall, safe installer, encrypted DNS service configs, systemd units, dry-run, backup/restore, docs and deterministic mocked tests. Provide a complete manual configuration example that works in a disposable VM. No unrequested production deployment.

**Phase 2 — client full-tunnel and persistent kill switch:** importable standard `wg-quick` profiles, strict `nftables` bootstrap + persistent rules, boot ordering, optional guided installer, client DNS policy, IPv4/IPv6 no-bypass tests, rollback controls. This is REQUIRED before marketing as leak-protected.

**Phase 3 — real VM validation:** isolated 2-3 host test lab, true handshake, connection to Internet, DNS/IPv4/IPv6 captures, revocation, all failure simulations, SSH safety, recovery and regression against legacy DoT. Produce evidence and accurately mark tested/not tested.

**Phase 4 — hardening and performance:** security-review fixes, fuzz parsers where justified, instrumentation, reproducible build/release artifacts, deployment guide, benchmark and tuning decisions. Only after verified stable baseline.

While executing, finish as much as feasible within the current working session. Do not skip necessary implementation by producing only plans; do not blindly run destructive commands to claim completeness. After each phase summarize implemented files, commands, test results, blocked dependencies, untested claims and next phase. If limits are reached, leave a clean, usable checked-in intermediate state and explicit TODO/release gates.

## 14. UX, COMMAND REFERENCE, AND DOCUMENTATION STANDARDS

Desired administrator flow (illustrative; make the real CLI consistent with docs):

```bash
shadowborn doctor
shadowborn init --dry-run
shadowborn plan --json
sudo shadowborn apply --confirm
sudo systemctl enable --now wg-quick@wg-shadowborn
sudo shadowborn peer add --name kali-laptop --public-key CLIENT_PUBLIC_KEY_PLACEHOLDER
sudo shadowborn peer list
sudo shadowborn status --verbose
sudo shadowborn peer revoke --name kali-laptop --confirm
sudo shadowborn restore --dry-run
```

Desired Linux client flow (standard WireGuard, example only):

```bash
sudo install -m 0600 /path/to/securely-transferred/wg-shadowborn.conf /etc/wireguard/wg-shadowborn.conf
sudo systemctl enable --now wg-quick@wg-shadowborn
sudo wg show
```

Strict client firewall must be installed/configured **before** bringing up the WG interface when strict leak prevention is requested. Documentation MUST NOT present the above minimal WG startup as sufficient to guarantee a kill switch.

Provide English README, optional Polish guide, configuration schema, install/uninstall/update/rollback, requirements, support matrix, key enrollment and secure transfer, server firewall rules, DNS privacy model, incident response, independent validation and benchmarks. README first paragraph must state this is a self-hosted server that uses standard WireGuard clients, not a commercial anonymity service. Keep existing `assets/shadow-mist-rounded-icon.png` with attribution if applicable. Update `docs/project-tree.txt` if used.

## 15. REFERENCE MATERIAL AND COMPLIANCE

Use official primary sources for technical design, verify against current installed versions:

- WireGuard: https://www.wireguard.com/quickstart/ and https://www.wireguard.com/protocol/
- `wg` reference: https://man7.org/linux/man-pages/man8/wg.8.html
- `wg-quick` full routes and kill-switch caveats: https://man7.org/linux/man-pages/man8/wg-quick.8.html
- nftables NAT/chain hooks: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks and https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29
- Inspiration ONLY: Mistborn, https://gitlab.com/cyber5k/mistborn. Study its server + WireGuard + DNS integration, security boundaries, and administrative UX. **Do not copy old code, configuration, dependencies or license without checking ownership, compatibility, security and current maintenance state.** We want a smaller, cleaner modern kernel WireGuard + nftables design.

Security is additive only where the threat model justifies it. Standard cryptographic primitives + correct firewall, key custody and leak testing beat an exotic pile of encrypted wrappers.

## 15A. CRITICAL NETWORK LEAK BOUNDARIES AND REAL-WORLD ROUTING

- **Per-hop clarity:** client's ISP / LAN sees only **outer WireGuard UDP**, tunnel endpoint IP, packet sizes/timing and unavoidable local-link control traffic while protected. The VPS provider/host network can see the server's clear IP-layer egress destination and metadata. HTTPS/TLS remains responsible for payload confidentiality from the VPS to websites. A site sees the VPS public IP, but browsers/accounts may still identify the user.
- **Two-sided enforcement:** server rules can enforce which authenticated peers may forward and where; ONLY the client host can guarantee its own default-deny policy when tunnel fails. Never write docs suggesting server-side firewall alone makes an unmodified client leak-proof.
- **Kill switch architecture:** base nftables rules must be persistent independently of WireGuard interface lifecycle; use `inet` family to cover IPv4+IPv6, including physical interface changes. Use policy routing/fwmark correctly so encrypted outer WG UDP alone can reach the fixed authorized server endpoint. Assert DENY-by-default when `wg-quick` is stopped or crashes, before DNS/WG startup, and after reboot. Enforce predictable ordering: firewall first, tunnel second; stop tunnel never removes protection. Recovery requires console/admin opt-in, not implicit fail-open.
- **Allowlist threat boundary:** DHCP/DHCPv6, ARP, NDP or other non-IP local control may be indispensable for reaching the VPN; allow only what is required on explicitly approved interfaces. Local network broadcast/metadata may still be visible on LAN. Never allow generic `udp dport 53`, all traffic on UDP/51820, or arbitrary IP:443 on physical interfaces as a fallback.
- **Domain/endpoint changes:** IPv4/IPv6 server endpoint pinning avoids DNS-bootstrap dependence and simplifies physical-interface allowlist. A server IP change must trigger explicit verified migration, staged allowlist updating, and no transient default-open window. Hostnames can be supported only with a secure, testable bootstrap design; do not add a general DNS exception that undermines the fail-closed policy.
- **Prevent accidental path bypasses:** inspect multiple routing tables, policy rules, IPv6 RA, VPN competition, Docker networking, local proxies, route reinstallation by NetworkManager, and container/VM traffic. Do not claim host protection for containers or guests until tested. Lo/Unix sockets are local and not sent over the tunnel; LAN and captive portal exemptions are explicit and clearly labeled weakened mode.
- **Verification method:** observe actual packets on the physical client NIC(s) (`tcpdump`) and the WG interface in an isolated controlled test. Tests must include both successful outbound HTTPS and controlled tunnel outage; assert absence of unintended physical IPv4/IPv6 destination packets. `wg show` handshake, a successful `curl`, or absence of captured port-53 packets alone NEVER proves universal no-leak enforcement.

## 15B. SERVER HARDENING, CLOUD PORTABILITY AND RECOVERY

- Initially target an isolated Debian/Ubuntu VPS in Germany for testing. Keep provider-independent interfaces, configurable WAN, endpoint/port, cloud SG rules, IPv4/IPv6 subnet and routing; deployments to other providers/regions must require **no source edits**. No jurisdiction is a security guarantee.
- Prefer a minimal, maintained distribution, kernel WireGuard, `wireguard-tools`, `nftables`, Unbound with hardened policy, and native systemd. No mandatory Docker, web control panel, reverse proxy, analytics, Tor, multi-hop, or DNS-tunnel transport.
- Establish strong SSH administration only after proving an operator has at least one working alternate access path. Do not remove cloud management agents, sshd, firewall policies, login records or backups outside Shadowborn's ownership; no "burn the server" automation, destructive log cleanup or filesystem wipe.
- Keep a clear, tested `bootstrap -> plan -> apply -> verify -> status -> backup/restore -> update -> uninstall` cycle. Initial install and update never auto-apply networking. Existing firewall, routes, cloud init, and resolvers must be inspected for collisions; abort safely if ambiguous.
- With each peer, allocate a unique tunnel IPv4/IPv6 address and maintain only minimal authorization state, not activity history. Protect PSKs and private keys from shell histories, process arguments where feasible, service logs and CI. Rotate/revoke without producing historical activity records; drop revoked peer from running WG and persisted configuration atomically.
- Support reproducible rebuilding of the gateway from protected secrets/configuration backups plus infrastructure-as-code examples. Backups may necessarily contain **secrets and authorized peer inventory**, so require encryption, restricted access and explicit retention controls; they must not contain user traffic metadata or sessions. No promise that deleting a VPS erases the provider's snapshots or external logs.
- Declare release gates for *SSH lockout*, *open DNS resolver*, *unexpected IPv6 egress*, *peer-to-peer lateral movement*, *unexpected routing to cloud metadata addresses*, *tunnel down bypass*, *rollback failure*, and *VPN credentials exposed to logs*.

## 15C. DNS ARCHITECTURE, MISTBORN INSPIRATION, OPTIONAL PI-HOLE

**Required v1 DNS path:** client uses the tunnel-side resolver address; query crosses WireGuard; server-side Unbound listens only on the tunnel and forwards with authenticated DNS-over-TLS to Quad9 (or another explicitly approved secure resolver). Enable cache with privacy-respecting options and optionally DNSSEC validation where supported. Never expose recursion to public WAN. Never silently fall back to port-53 plaintext upstream. Separate operational DNS *availability* from *privacy* status; DNS outage in strict mode is not permission for physical DNS leakage.

**No logs, for every DNS component:** no query logs, no client-address histories, no resolver telemetry or stored time series. Test actual resolver config and journal/service behavior. DNS cache is volatile resolution state, not browsing history to persist; disable persistent cache dumps. Upstream Quad9 can see requested names, and VPS provider might see encrypted upstream connection metadata. Do not promise zero external logs.

**Future plugin design (not mandatory for v1):** Pi-hole on the VPN side of the server for ad/tracker blocking; optionally `dnscrypt-proxy` for DNSCrypt upstream instead of DoT. Correct ordering: `VPN client -> WireGuard -> Pi-hole (optional) -> Unbound/cache or dnscrypt-proxy (selected path) -> authenticated upstream resolver`. Avoid accidental circular upstream dependencies or enabling multiple parallel resolver chains. Ensure Pi-hole query history and long-term database persistence are OFF; validate actual settings in the installed version. Do not ship Pi-hole, dashboards or `dnscrypt-proxy` as prerequisites for the first secure tunnel.

Mistborn is architecture inspiration only (WireGuard + DNS/privacy + client management). Its entire legacy web services stack and dependencies are not the definition of this project. Review licensing and current security state before copying anything; prefer fresh code and official upstream packages.

## 15D. CRYPTOGRAPHY AND PERFORMANCE DECISIONS

- **WireGuard is the cryptographic transport**, not proprietary "super encryption". Use kernel WG's native Noise-based protocol/ChaCha20-Poly1305/Curve25519; one pair of keys per device and optional **independent PSK per peer** where practical. Do not layer amateur cryptography, artificial packet framing, DNS tunnels or custom packet transforms on top for the sake of claiming greater strength.
- Optimize for **correctness first and measured throughput second**: minimal packet path, kernel forwarding and nftables, efficient DNS caching, optional MTU tuning based on PMTUD, constrained conntrack use. Measure baseline latency/throughput and CPU on controlled endpoints; publish measured improvements, never invented numbers.
- Distinguish service uptime from link security. WireGuard standard roaming/keepalive and systemd restart behavior should recover outages where possible; a strict kill switch deliberately blocks connectivity until the approved tunnel returns. Never promise uninterrupted internet under a server outage, or "unbreakable" cryptography.
- A PSK is *additional secrecy input*, not a single reusable password to authorize every device. The simple import experience comes from protected per-device `.conf` profiles and explicit admin authorization. Provide safe, practical steps to generate and transfer a profile securely, preferably client-generated private keys.

## 15E. OPERATING PROFILES, CLIENT SUPPORT, AND PRODUCT UX

- Server configuration profiles: `baseline` (security defaults with simple operator setup) and `hardened` (stricter peer/LAN/DNS policies, still debuggable and high performance). Both are no-activity-logs. They do not turn all host-wide logs off.
- Linux client modes: `standard` (regular WireGuard client; does **not** claim to prevent every bypass) and `strict` (install verified persistent firewall + network/suspend/restart protections). `strict` requires explicit user consent and may block the Internet during outages. `observe`/`plan` provide read-only information.
- OS support should be a verified **matrix**, not "every Linux" marketing. First target current supported Debian/Ubuntu server and Kali/Debian/Ubuntu systemd clients. Then add Fedora/Arch on verified adapters with all assumptions called out.
- Default deployment has no public web dashboard. Prefer a clear Rust CLI and official `wg-quick` importable clients for Linux/mobile/other systems. Non-Linux clients may join via standard WG apps, but project **does not claim a verified persistent client kill switch** on those platforms.
- Suggested CLI conventions (implement honestly): `shadowborn doctor`, `shadowborn plan`, `sudo shadowborn apply --confirm`, `shadowborn server status`, `shadowborn peer add`, `peer revoke`, `peer list`, `shadowborn client profile`, `shadowborn client lockdown plan/enable/disable`, `shadowborn dns status`, `shadowborn restore`, `shadowborn version`; the actual help and README must match implemented commands.

## 16. DEFINITION OF DONE

A release candidate is acceptable only when:

- New repo naming and docs are coherent; old installed Shadow Mist client and its state are not accidentally broken.
- Owner can install on a fresh supported VPS, approve a safe `plan`, and obtain a working WG server with deterministic persistent configuration.
- A new standard WireGuard Linux client can enroll with per-device credentials, reach ordinary websites through the VPN, and appear to destination sites via the server's public egress IP.
- Default peer-to-peer/host/LAN/cloud metadata access is denied; internet egress works by proper forwarding/NAT or routed IPv6.
- Strict client firewall, once **explicitly enabled**, blocks unintended non-WG Internet traffic on boot, tunnel down, Wi-Fi changes and dual-stack paths. If a test cannot be performed, do not call it leak-proof.
- DNS client→server is in WG, server→upstream DoT validated, no external open recursion, and observed leaks are accurately reported.
- Peer revocation persists across daemon/server restarts; no project-owned persistent activity logs exist, and key material never appears in Git, output of services, or telemetry. The product-level no-logs tests pass; OS/provider visibility limits are explicitly documented.
- Admin can audit, back up, roll back and uninstall only project-owned changes safely without losing SSH access.
- Tests and reproducible evidence from synthetic lab fixtures are documented with honest release gates; performance figures are measured.

## 17. START WORK NOW

1. Inspect the real repository and report actual baseline. Never assume this document is already implemented.
2. Implement Phases 0 and 1 with real code, tests and documentation; proceed to Phase 2 and later phases where safe and feasible.
3. Avoid applying system changes on the developer workstation. Use isolated test namespace/VM for live changes.
4. Show exact commands for a **fresh server** installation and a **standard client** import separately.
5. Do not change user GitHub settings or push/force-push unless specifically requested.
6. Be candid about security and completion; no software can guarantee that 'nothing can ever get through' under every attacker and failure model.
