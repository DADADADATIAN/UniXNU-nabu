#!/usr/bin/env python3
"""Derive the small build input from a user-owned iPadOS 17.7 (21H16) IPSW.

The kernel build only needs the BuildManifest plus four small members (the
kernel cache, the device tree and the two static trust caches).  This script
extracts exactly those members from a local Restore IPSW, verifies each member
against the board's pinned sha256, and repacks them as a deterministic zip
(fixed timestamps, sorted entries, no extra fields) so independently produced
archives compare byte-for-byte.  The full IPSW and this derived archive stay
out of the repository: they contain Apple copyrighted content.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import zipfile

PRODUCT = 'iPad7,11'
VERSION = '17.7'
BUILD = '21H16'
DEVICE_CLASS = 'j171ap'
CHIP_ID = 0x8010
BOARD_ID = 0x1C
SECURITY_DOMAIN = 1
# board.toml [ipsw] fetch list.
COMPONENTS = ('KernelCache', 'DeviceTree', 'StaticTrustCache', 'Cryptex1,SystemTrustCache')
# board.toml [ipsw.sha256] member pins.
MEMBER_SHA256 = {
    'kernelcache.release.ipad7c': '2c395d03d21129d79f4ad9648fe30b1dd8fc62b17f180b79976604102a4678ba',
    'DeviceTree.j171ap.im4p': '1d5ce5ee967b98df2b0017931d3a18b77add92f8902b42b12061ab5e21fd0ebb',
    '044-17597-018.dmg.trustcache': '7640ab0933ba6a9048b6de8cf7e1e0d4806350c5eb2ccb3bc1284b79b1499e2d',
    '044-18090-018.dmg.trustcache': '381d0eeb39949a4ed9cbca7f89ae3442fa37e9afcaaa5f1314465b43aaa46ea4',
}
# sha256 of the archive this project itself used (private release asset
# unixnu-source-inputs/ipsw-21h16-small.zip).  Reproduced output must match.
EXPECTED_ARCHIVE_SHA256 = 'fce1ea205e571c3850e150404fc04f255f1192ba19c68e12497c19b8f87d8994'
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def identity(manifest):
    m = manifest
    if (m['ProductVersion'], m['ProductBuildVersion']) != (VERSION, BUILD) or \
            PRODUCT not in m['SupportedProductTypes']:
        raise SystemExit(f'this IPSW is {m["ProductVersion"]} ({m["ProductBuildVersion"]}) '
                         f'for {", ".join(m["SupportedProductTypes"])}; expected '
                         f'{VERSION} ({BUILD}) for {PRODUCT}')
    for item in m['BuildIdentities']:
        info = item['Info']
        if (info['DeviceClass'] == DEVICE_CLASS and info['RestoreBehavior'] == 'Erase'
                and int(item['ApChipID'], 16) == CHIP_ID and int(item['ApBoardID'], 16) == BOARD_ID
                and int(item['ApSecurityDomain'], 16) == SECURITY_DOMAIN):
            return item
    raise SystemExit(f'no Erase build identity for {DEVICE_CLASS} in this IPSW')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ipsw', type=Path, required=True,
                   help='user-owned iPad_10.2_17.7_21H16_Restore.ipsw')
    p.add_argument('--output', type=Path, required=True,
                   help='destination ipsw-21h16-small.zip (must not exist)')
    args = p.parse_args()
    if not args.ipsw.is_file():
        raise SystemExit('IPSW not found: ' + str(args.ipsw))
    if args.output.exists():
        raise SystemExit('Refuse to overwrite: ' + str(args.output))
    source = zipfile.ZipFile(args.ipsw)
    manifest = plistlib.loads(source.read('BuildManifest.plist'))
    board = identity(manifest)
    members = {}
    for component in COMPONENTS:
        try:
            name = board['Manifest'][component]['Info']['Path']
        except KeyError:
            raise SystemExit(f'component {component} is not in this IPSW') from None
        members[component] = name
    entries = {'BuildManifest.plist': source.read('BuildManifest.plist')}
    digests = {}
    for component, name in sorted(members.items(), key=lambda item: item[1]):
        data = source.read(name)
        actual = hashlib.sha256(data).hexdigest()
        pin = MEMBER_SHA256.get(Path(name).name)
        if pin is not None and actual != pin:
            raise SystemExit(f'{name} differs from the pinned sha256: {actual}')
        digests[name] = actual
        entries[name] = data
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0o600 << 16
            target.writestr(info, entries[name])
    archive_sha = hashlib.sha256(args.output.read_bytes()).hexdigest()
    report = {'ipsw': str(args.ipsw), 'product': PRODUCT, 'version': VERSION,
              'build': BUILD, 'device_class': DEVICE_CLASS,
              'members': {k: v for k, v in sorted(digests.items())},
              'archive_sha256': archive_sha,
              'archive_matches_project_input': archive_sha == EXPECTED_ARCHIVE_SHA256,
              'note': 'Apple copyrighted content; keep this archive and the IPSW out of any repository.'}
    report_path = args.output.with_suffix('.json')
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'archive_sha256': archive_sha,
                      'matches_project_input': archive_sha == EXPECTED_ARCHIVE_SHA256}))
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        print('Note: member hashes match but the zip bytes differ from the project '
              'private input; check compression/ordering or record this archive hash '
              'as the input identity for your own builds.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
