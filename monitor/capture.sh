#!/usr/bin/env sh
set -eu

IFACE="${IFACE:-eth0}"
OUTDIR="${OUTDIR:-/data/pcap}"
FILENAME="${FILENAME:-baseline_$(date +%Y%m%d_%H%M%S).pcap}"

mkdir -p "$OUTDIR"
echo "[tcpdump] Capturing on $IFACE -> $OUTDIR/$FILENAME"
exec tcpdump -i "$IFACE" -w "$OUTDIR/$FILENAME" -U
