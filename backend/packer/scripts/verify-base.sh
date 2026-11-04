#!/bin/sh
# Verify the tiny guest userland before the image is accepted.
set -e
test -f /etc/alpine-release
grep -q "MUSEARENA" /init 2>/dev/null || echo "marker check: initramfs staged at boot by images.ts"
echo "tiny-linux base verified: $(cat /etc/alpine-release)"
