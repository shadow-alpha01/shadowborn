# Persistent client protection — not released

Standard profiles are importable but not leak-proof. `client lockdown plan/status`
reports UNSUPPORTED and enforced=false; enable/disable exit nonzero. A client
lockdown installer is not provided until these release gates are met. No client
firewall is applied by current code.

Before implementation may be enabled, test a persistent inet default-deny policy
independent of WG lifecycle, pinned endpoint + fwmark outer-UDP exceptions,
approved interface-specific DHCP/NDP, boot ordering, route/network changes,
sleep/resume, DNS outage, IPv6 bypass, endpoint migration and rollback. Never
allow arbitrary UDP/51820, physical DNS or blanket LAN exemptions. PF_PACKET and
local-link control need separate scope statements. Container/VM traffic is not
covered without dedicated tests. Recovery must require explicit console consent.
