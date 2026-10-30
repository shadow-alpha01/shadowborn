#!/bin/sh
set -eu
printf '%s\n' 'UNSUPPORTED: strict client activation is blocked pending persistent firewall, boot and packet-level leak validation.' >&2
exit 4
