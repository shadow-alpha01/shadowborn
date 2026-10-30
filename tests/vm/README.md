# Outstanding VM acceptance

Use disposable gateway, client and observer VMs with console access and invented
peer identities. Take protected configuration snapshots. Follow the manual server
and client guides; never apply test networking on the developer workstation.

Required evidence: authorized HTTPS/egress IP; IPv4/IPv6 captures on both physical
and WG interfaces; DoT certificate failure; public DNS recursion denied; SSH
preserved; peer/host/metadata isolation; persistent revoke; boot and failure
recovery; no activity logs after traffic, DNS failure, restart and reboot.
Strict tests require an implementation first: boot ordering, Wi-Fi/Ethernet,
sleep, alternate routes, WG down, endpoint migration and container boundaries.
All unexecuted cases stay NOT TESTED. Never upload real keys or customer captures.
