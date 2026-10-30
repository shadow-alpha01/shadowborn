# Threat model

| Actor or failure | Intended boundary | Remaining exposure |
| --- | --- | --- |
| ISP, hostile LAN/AP | WireGuard encrypts device-to-VPS traffic | Endpoint, timing, sizes and local link identifiers remain visible |
| VPS provider/operator | HTTPS independently protects application content | Egress destinations and other metadata remain visible |
| External attacker | Per-device WG authentication; SSH allowlist; VPN-only resolver | Host/kernel vulnerabilities and management credentials |
| Compromised peer | Per-key /32 source restriction, default peer/host/private-network deny | Its authorized Internet use; implementation defects |
| Lost laptop | Unique key/PSK and explicit revocation | Stored credentials and past disclosures; live revoke currently unsupported |
| Admin error | Schema checks, offline locks, atomic files, compare-before-write | Manual VM deployment can lock out SSH; console/snapshot required |
| Tunnel/DNS/server outage | Strict client should deny bypass | Strict mode not implemented; standard client can bypass when routes disappear |
| Privileged malware | Outside the VPN boundary | Kernel, raw sockets, firmware, secrets, application data |

No anonymous/untraceable, post-quantum, zero-provider-log or uninterrupted-Internet
promise. WireGuard covers one hop. A server cannot enforce a disconnected
client's firewall. Browser fingerprints/accounts are independent of IP address.
The actual verification matrix, not a successful handshake, defines assurance.
