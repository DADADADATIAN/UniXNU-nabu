#!/bin/sh
# Reproduce the proven nabu source-build pipeline on a host with Xcode.
#
# This mirrors the project CI (workflows/unixnu-source.yml) exactly:
#   1. stage a writable device directory (board-baseline.toml in place of the
#      format-2 board.toml - prepare_source.py rewrites it per profile)
#   2. source-ci/prepare_source.py assembles/patches the pinned upstream tree
#   3. ./unixnu defconfig + ./unixnu build kernel inside that tree
#   4. optional GPU userprobe archive
#   5. source-ci/collect_outputs.py records the candidate + evidence manifest
#
# Usage:
#   source-ci/nabu-build.sh --upstream <UniXNU checkout> --profile <defconfig> \
#       --work <fresh output dir> [--capture-logs] [--gpu-userprobe] [--ui-watch]
#
# Required environment (same names as CI):
#   UNIXNU_IPSW                    path to ipsw-21h16-small.zip
#                                 (make yours: source-ci/prepare_ipsw_input.py)
#   UNIXNU_OWNER_POLICY            extracted nabu owner OS policy dir
#   UNIXNU_OWNER_POLICY_SYSTEMOS   extracted SystemOS policy dir
#   UNIXNU_DISPLAY_REFERENCE       dir with kernel.macho (display/CPU profiles)
# See docs/BUILD-INPUTS.zh-CN.md for how each input is produced.
set -eu

DEVICE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
UPSTREAM= PROFILE= WORK= EXTRA=
while [ $# -gt 0 ]; do
    case "$1" in
        --upstream) UPSTREAM=$2; shift 2 ;;
        --profile)  PROFILE=$2;  shift 2 ;;
        --work)     WORK=$2;     shift 2 ;;
        --capture-logs|--gpu-userprobe|--ui-watch) EXTRA="$EXTRA $1"; shift ;;
        *) echo "nabu-build.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$UPSTREAM" ] && [ -n "$PROFILE" ] && [ -n "$WORK" ] || {
    echo 'usage: nabu-build.sh --upstream DIR --profile DEFCONFIG --work DIR [flags]' >&2; exit 2; }
[ ! -e "$WORK" ] || { echo "nabu-build.sh: $WORK must not exist" >&2; exit 1; }
[ -f "$UPSTREAM/unixnu" ] || { echo "nabu-build.sh: $UPSTREAM is not a UniXNU checkout" >&2; exit 1; }
for var in UNIXNU_IPSW; do
    eval "value=\${$var:-}"
    [ -n "$value" ] || { echo "nabu-build.sh: set $var (see docs/BUILD-INPUTS.zh-CN.md)" >&2; exit 1; }
done
case "$PROFILE" in
    nabu_qemu_root_defconfig|nabu_qemu_data_defconfig|nabu_qemu_cpu_ui_defconfig|\
    nabu_qemu_legacy_defconfig|nabu_qemu_cpu_present_defconfig|\
    nabu_ufs_root_defconfig|nabu_ufs_data_defconfig|nabu_ufs_cpu_ui_defconfig|\
    nabu_ufs_cpu_present_defconfig|nabu_ufs_gpu_defconfig|nabu_ufs_gpu_metal_defconfig)
        for var in UNIXNU_OWNER_POLICY UNIXNU_OWNER_POLICY_SYSTEMOS; do
            eval "value=\${$var:-}"
            [ -n "$value" ] || { echo "nabu-build.sh: set $var for $PROFILE" >&2; exit 1; }
        done ;;
esac
case "$PROFILE" in
    nabu_qemu_legacy_defconfig|nabu_qemu_cpu_present_defconfig|\
    nabu_ufs_cpu_present_defconfig|nabu_ufs_gpu_defconfig|nabu_ufs_gpu_metal_defconfig)
        [ -n "${UNIXNU_DISPLAY_REFERENCE:-}" ] || {
            echo "nabu-build.sh: set UNIXNU_DISPLAY_REFERENCE for $PROFILE" >&2; exit 1; } ;;
esac

# Stage the writable device copy: prepare_source.py mutates board.toml during
# profile selection, so it must not touch the checked-in format-2 record.
STAGED="$WORK/device"
mkdir -p "$STAGED"
cp "$DEVICE/source-ci/board-baseline.toml" "$STAGED/board.toml"
for item in configs scripts patches platform ufs gpu usb userprobe vendor; do
    [ -e "$DEVICE/$item" ] && cp -a "$DEVICE/$item" "$STAGED/$item"
done

py=python3
command -v python3 >/dev/null 2>&1 || py=py
RUN_ID=${NABU_RUN_ID:-$(date +%s)}
HEAD_SHA=$(git -C "$UPSTREAM" rev-parse HEAD)
INPUT_SHA=$(sha256sum "$UNIXNU_IPSW" | cut -d' ' -f1 2>/dev/null || \
            shasum -a 256 "$UNIXNU_IPSW" | cut -d' ' -f1)

echo "== prepare_source: $PROFILE"
# shellcheck disable=SC2086
"$py" "$DEVICE/source-ci/prepare_source.py" --upstream "$UPSTREAM" --device "$STAGED" \
    --profile "$PROFILE" --report "$WORK/source-prepare.json" $EXTRA

echo "== unixnu defconfig + build kernel"
(cd "$UPSTREAM" && ./unixnu defconfig "$PROFILE" && ./unixnu build kernel)

if [ "${NABU_GPU_USERPROBE:-0}" = 1 ]; then
    "$py" "$STAGED/scripts/build-nabu-gpu-userprobe.py" --output "$UPSTREAM/out/nabu/userprobe"
fi

echo "== collect_outputs"
"$py" "$DEVICE/source-ci/collect_outputs.py" --upstream "$UPSTREAM" --device "$STAGED" \
    --output "$WORK/source-output" --run-id "$RUN_ID" --attempt 1 \
    --head-sha "$HEAD_SHA" --build-outcome success \
    --input-sha256 "$INPUT_SHA" --prepare-report "$WORK/source-prepare.json"

echo "nabu-build.sh: candidate at $UPSTREAM/out/nabu/kernel/kernel.macho"
echo "nabu-build.sh: evidence at $WORK/source-output/"
