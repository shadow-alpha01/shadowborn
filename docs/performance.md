# Performance

No throughput/latency/CPU benchmark has been run or published for Shadowborn.
The intended data path is kernel WireGuard, nftables and ordinary kernel routing.
No custom packet relay, nested transport or default sysctl/BBR/MSS tuning exists.

Use owned isolated endpoints to compare direct/tunneled TCP and UDP throughput,
loss/jitter, CPU, PMTUD, reconnect latency and DNS p50/p95. Record distro, kernel,
architecture, VPS NIC/size, MTU and topology. Namespace connectivity checks are
not Internet benchmarks. Tune only measured bottlenecks and preserve rollback.
