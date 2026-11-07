#!/usr/bin/env bash
# CI-only preparation for the nabu kernel compile check.
#
# Reproduces, from public inputs only, the parts of the device repository's
# private source-ci/prepare_source.py that the public workflow can satisfy:
#   * drop the two union patches the core series already applies,
#   * refresh the context line of nabu-master-second-trust-cache.patch,
#   * turn the pinned dependency guards into warnings (ci-relax-build-gates.py),
#   * stage the IPSW kernelcache and hand it to the archive builders, which read
#     UNIXNU_KERNELCACHE from the environment that unixnu builds.
#
# Nothing here changes kernel source or the link inputs; a real compile or link
# failure still fails the build.
set -euo pipefail

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
SERIES_DIR="$DEVICE_DIR/patches/xnu"
KERNELCACHE="$WORKSPACE/.cache/nabu-kernelcache"

echo 'ci-prepare: device patch series'
grep -vE 'nabu-union-(lower-directory|getattrlistbulk)\.patch' "$SERIES_DIR/series" > "$SERIES_DIR/series.tmp"
mv "$SERIES_DIR/series.tmp" "$SERIES_DIR/series"
sed -i.bak \
  's|\[ VM_BASE config_kasan config_ubsan config_kcov config_ksancov \]|[ VM_BASE dynamic_codesigning kernel_tagging kernel_tbi config_kasan config_ubsan config_kcov config_ksancov ]|' \
  "$SERIES_DIR/nabu-master-second-trust-cache.patch"
sed -n '1,20p' "$SERIES_DIR/series"

echo 'ci-prepare: relax the pinned dependency guards'
python3 "$DEVICE_DIR/source-ci/ci-relax-build-gates.py" "$WORKSPACE/scripts/build-xnu-4k-baseline.sh"

echo 'ci-prepare: stage the IPSW kernelcache'
python3 - "$DEVICE_DIR" "$WORKSPACE/.cache" "$KERNELCACHE" <<'PY'
"""Extract the arm64 kernelcache of board.toml [ipsw] for the archive builders."""
import hashlib
import plistlib
import shutil
import struct
import subprocess
import sys
import tomllib
import urllib.request
import zipfile
from pathlib import Path

CHUNK = 1 << 20


def sha256_of(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def der(data, at):
    tag, length = data[at], data[at + 1]
    at += 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[at:at + count], 'big')
        at += count
    return tag, at, length


def im4p_payload(data):
    tag, start, length = der(data, 0)
    if tag != 0x30:
        raise SystemExit('stage-kernelcache: the KernelCache member is not an IM4P')
    at, items = start, []
    while at < start + length:
        _, body, size = der(data, at)
        items.append(data[body:body + size])
        at = body + size
    if len(items) < 4 or items[0] != b'IM4P':
        raise SystemExit('stage-kernelcache: the KernelCache member is not an IM4P')
    return items[3]


def download(url, destination):
    partial = destination.with_suffix('.partial')
    if shutil.which('curl'):
        print(f'stage-kernelcache: curl {url}', flush=True)
        subprocess.run(['curl', '-L', '--fail', '--retry', '3', '--retry-delay', '5',
                        '-o', str(partial), url], check=True)
    else:
        print(f'stage-kernelcache: urllib {url}', flush=True)
        with urllib.request.urlopen(url) as source, partial.open('wb') as target:
            while chunk := source.read(CHUNK * 8):
                target.write(chunk)
    partial.rename(destination)
    print(f'stage-kernelcache: downloaded {destination.stat().st_size >> 20} MiB', flush=True)


def main():
    device, cache, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    board = tomllib.loads((device / 'board.toml').read_text(encoding='utf-8'))
    spec = board['ipsw']
    pin = board.get('kernel', {}).get('prelink', {}).get('kernelcache_sha256')
    if out.is_file() and (pin is None or sha256_of(out) == pin):
        print(f'stage-kernelcache: reused {out}')
        return
    cache.mkdir(parents=True, exist_ok=True)
    ipsw = cache / Path(spec['url']).name
    if not ipsw.is_file() or ipsw.stat().st_size < (1 << 30):
        download(spec['url'], ipsw)
    with zipfile.ZipFile(ipsw) as archive:
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        if (manifest['ProductVersion'], manifest['ProductBuildVersion']) != (spec['version'], spec['build']):
            raise SystemExit(f"stage-kernelcache: this IPSW is {manifest['ProductVersion']} "
                             f"({manifest['ProductBuildVersion']}), the board expects "
                             f"{spec['version']} ({spec['build']})")
        identity = None
        for item in manifest['BuildIdentities']:
            info = item['Info']
            if (info['DeviceClass'] == spec['device_class'] and info['RestoreBehavior'] == 'Erase'
                    and int(item['ApChipID'], 16) == spec['chip_id']
                    and int(item['ApBoardID'], 16) == spec['board_id']):
                identity = item
                break
        if identity is None:
            raise SystemExit('stage-kernelcache: no Erase identity for this board in the IPSW')
        member = identity['Manifest']['KernelCache']['Info']['Path']
        print(f'stage-kernelcache: member {member}')
        packed = im4p_payload(archive.read(member))
    lzfse = out.with_suffix('.lzfse')
    fat = out.with_suffix('.fat')
    lzfse.write_bytes(packed)
    subprocess.run(['/usr/bin/compression_tool', '-decode', '-a', 'lzfse',
                    '-i', str(lzfse), '-o', str(fat)], check=True)
    data = fat.read_bytes()
    lzfse.unlink()
    fat.unlink()
    if data[:4] == b'\xca\xfe\xba\xbe':
        count = struct.unpack('>I', data[4:8])[0]
        slices = [struct.unpack('>5I', data[8 + 20 * i:28 + 20 * i]) for i in range(count)]
        arm64 = [s for s in slices if s[0] == 0x0100000c]
        if len(arm64) != 1:
            raise SystemExit('stage-kernelcache: expected exactly one arm64 slice')
        _, _, offset, size, _ = arm64[0]
        data = data[offset:offset + size]
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise SystemExit('stage-kernelcache: the decoded kernelcache is not a 64-bit Mach-O')
    out.write_bytes(data)
    digest = sha256_of(out)
    if pin and digest != pin:
        out.unlink()
        raise SystemExit(f'stage-kernelcache: kernelcache sha256 {digest} does not match the '
                         f'board pin {pin}')
    print(f'stage-kernelcache: {out} {len(data)} bytes sha256 {digest}')
    for stale in (ipsw, ipsw.with_suffix('.partial')):
        if stale.is_file():
            stale.unlink()


main()
PY

echo 'ci-prepare: hand the kernelcache to the archive builders'
python3 - "$WORKSPACE/scripts/unixnu/kernel.py" <<'PY'
"""Export UNIXNU_KERNELCACHE for build_archives, which reads it from the environment."""
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
inject = ("    staged = Path(ctx.root) / '.cache/nabu-kernelcache'\n"
          "    if staged.is_file():\n"
          "        env = dict(env, UNIXNU_KERNELCACHE=str(staged))\n")
# build_archives starts its environment in one of two ways depending on the
# script revision; both are still the right place to hand over the kernelcache.
ANCHORS = [
    "    env = dict(env, PATH=toolchain_path(env.get('PATH')), UNIXNU_DEVICE=str(ctx.device))\n",
    "    env = dict(env, PATH=toolchain_path())\n",
]
if 'nabu-kernelcache' in text:
    print('ci-prepare: kernel.py already exports UNIXNU_KERNELCACHE')
else:
    for anchor in ANCHORS:
        if anchor in text:
            path.write_text(text.replace(anchor, inject + anchor, 1), encoding='utf-8')
            print('ci-prepare: kernel.py now exports UNIXNU_KERNELCACHE')
            break
    else:
        raise SystemExit('ci-prepare: anchor missing in scripts/unixnu/kernel.py')
PY

echo 'ci-prepare: done'
