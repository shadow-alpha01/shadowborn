# DNS path

Generated path: device -> WireGuard -> tunnel-bound Unbound -> authenticated
Quad9 TCP/853. Upstream addresses and certificate name are pinned. The resolver
has explicit tunnel-prefix ACL and server firewall admits only authorized peer
addresses over WG. Plaintext forwarded client DNS to external port 53 is denied;
application DoH inside the tunnel remains possible.

The renderer uses forward-first=no, a CA bundle, zero verbosity, disabled
query/reply/SERVFAIL logs, disabled syslog, disabled remote control and no periodic
statistics/cache persistence. Verify with the installed unbound-checkconf and
actual service/journal observations. Transport privacy, DNS availability and
DNSSEC are different: local DNSSEC validation is not enabled in this preview;
Quad9 performs its upstream policy. Runtime DoT authentication is NOT TESTED.

Resolver outage must not authorize client physical DNS. Standard clients lack
that enforcement; the required strict integration is not yet implemented.
The upstream resolver sees requested names; external logging cannot be controlled.
See the [official Unbound configuration reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).
