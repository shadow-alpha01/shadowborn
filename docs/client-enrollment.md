# Client enrollment

Preferred flow: create keys on the device, send only its public key over an
already authenticated administrator channel. Never share device private keys.
On a standard Linux client with wireguard-tools:

```bash
umask 077
mkdir -m 0700 -p "$HOME/shadowborn-device"
cd "$HOME/shadowborn-device"
wg genkey > privatekey
wg pubkey < privatekey > publickey
```

Before VM activation, authorize that public key using `sudo shadowborn peer add
--name laptop --public-key DEVICE_PUBLIC_KEY`. The server assigns a unique /32
and generates a separate PSK. `peer export-public --name laptop` outputs public
configuration; `peer show --name laptop --redacted` hides keys. `peer list` has
no activity counters or timestamps.

Export `sudo shadowborn client profile --name laptop --output /root/laptop.template`.
Transfer the PSK-bearing template using authenticated encrypted transport or
an encrypted removable medium. Replace `<DEVICE_PRIVATE_KEY>` on the device with
its own private key using a local editor, without printing keys. The result is a
standard wg-quick config. Protect directory/file permissions as 0700/0600.

Optional convenience: `sudo shadowborn peer issue --name laptop --recipient
AGE_RECIPIENT --bundle /root/laptop.conf.age --accept-server-key-generation`.
This explicitly creates the client private key in server memory and immediately
encrypts the profile to a native age recipient. No plaintext convenience artifact
is written. Decrypt locally using the matching age identity into a 0600 file.
This does not provide the preferred device-only key custody.

On a separate, explicitly approved client VM:

```bash
sudo install -d -m 0700 /etc/wireguard
sudo install -m 0600 /path/to/completed/profile.conf /etc/wireguard/wg-shadowborn.conf
sudo systemctl enable --now wg-quick@wg-shadowborn.service
```

`DNS =` relies on wg-quick's resolvconf integration. Inspect the distro's DNS stack
and install the appropriate integration deliberately. Kali NetworkManager plus
systemd-resolved/Shadow Mist compatibility is NOT TESTED. Do not switch the
working laptop DNS implicitly. Use a pinned endpoint to avoid DNS bootstrap.

Both default address families route into the tunnel. This preview has IPv4-only
server egress; IPv6 is intentionally unavailable through it. **Standard mode has
no persistent kill switch**: stopping WG, resolver fallback or competing routing
can expose direct traffic. `client lockdown enable` is unsupported. Non-Linux WG
apps are best effort with no strict guarantee.

All peer mutations currently operate before deployment. A detected live/installed
gateway is rejected. For urgent revocation on the manual VM, use the console and
stop the tunnel until both kernel and persistent config have been updated; see
admin-recovery.md. Never assume a changed offline state invalidates old bundles.
