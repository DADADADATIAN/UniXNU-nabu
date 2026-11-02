#!/bin/sh
# Assemble the nabu ESP payload image from a resolved UniXNU tree.
#
# Usage:
#   scripts/package.sh <resolved unixnu tree> [extra unixnu payload args]
#
# The tree must already be configured and built for this device:
#   ./unixnu defconfig nabu_ufs_gpu_metal_defconfig -D <this repo>
#   ./unixnu fetch -D <this repo>
#   ./unixnu build kernel -D <this repo>
#
# board.toml [payload.adt] requires the per-device platform seed; pass it via
#   --unique-chip-id HEX (or UNIXNU_UNIQUE_CHIP_ID), plus the trust cache
#   sidecar with --trust-cache FILE and optional --data-ramdisk/--gpu-addon.
set -eu

DEVICE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TREE=${1:?usage: package.sh <resolved unixnu tree> [extra unixnu payload args]}
shift

cd "$TREE"
if [ ! -f out/nabu/kernel/kernel.macho ]; then
    echo 'package.sh: out/nabu/kernel/kernel.macho missing - run defconfig, fetch' >&2
    echo 'and "unixnu build kernel" for this device first' >&2
    exit 1
fi
exec ./unixnu payload -D "$DEVICE" "$@"
