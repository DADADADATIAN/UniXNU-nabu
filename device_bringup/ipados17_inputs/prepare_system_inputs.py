#!/usr/bin/env python3
"""Export selected local IPSW members into a new analysis directory, never a device.

Preserves the source IPSW. Reads each selected member fully, so zipfile checks its
CRC; this is not a whole-IPSW integrity or authenticity check. No full-file hash.
"""
import argparse
import json
import plistlib
import shutil
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

COMPONENTS = (
    'KernelCache', 'DeviceTree', 'StaticTrustCache',
    'Cryptex1,SystemTrustCache', 'OS', 'Cryptex1,SystemOS',
)
TZ = timezone(timedelta(hours=8))


def prepare(source, output, device_class):
    source = source.resolve(strict=True)
    before = source.stat()
    if output.exists():
        raise ValueError('output must be a new directory')
    report = {'source': str(source), 'source_bytes': before.st_size,
              'generated_at': datetime.now(TZ).isoformat(),
              'device_class': device_class, 'components': [],
              'device_accessed': False, 'whole_ipsw_hash_checked': False,
              'boot_compatibility_verified': False, 'status': 'exporting'}
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if names.count('BuildManifest.plist') != 1:
            raise ValueError('ambiguous or missing BuildManifest.plist')
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        if str(manifest.get('ProductVersion', '')).split('.')[0] != '17':
            raise ValueError('requires an iPadOS 17 input')
        if not any(p.startswith('iPad') for p in manifest.get('SupportedProductTypes', [])):
            raise ValueError('requires an iPad input')
        identities = [item for item in manifest['BuildIdentities']
                      if item['Info'].get('DeviceClass') == device_class
                      and item['Info'].get('RestoreBehavior') == 'Erase']
        if len(identities) != 1:
            raise ValueError('requires one unambiguous Erase build identity')
        identity = identities[0]
        selected = [(kind, identity['Manifest'][kind]['Info']['Path'])
                    for kind in COMPONENTS]
        for _, name in selected:
            if names.count(name) != 1:
                raise ValueError('ambiguous or missing member: ' + name)
        needed = sum(archive.getinfo(name).file_size for _, name in selected)
        output.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(output.parent).free < needed + (1 << 30):
            raise ValueError('not enough free space for components plus 1 GiB')
        output.mkdir()
        report.update(version=manifest['ProductVersion'],
                      build=manifest['ProductBuildVersion'],
                      products=manifest['SupportedProductTypes'],
                      chip_id=identity.get('ApChipID'),
                      board_id=identity.get('ApBoardID'))
        for kind, name in selected:
            member = archive.getinfo(name)
            destination = output / Path(name).name
            print(f'Exporting {kind}: {name} ({member.file_size:,} bytes)', flush=True)
            with archive.open(member) as reader, destination.open('xb') as writer:
                shutil.copyfileobj(reader, writer, 8 << 20)
            if destination.stat().st_size != member.file_size:
                raise ValueError('exported member length differs: ' + name)
            report['components'].append({
                'kind': kind, 'member': name, 'output': destination.name,
                'bytes': member.file_size, 'zip_crc32': f'{member.CRC:08x}',
                'zip_member_crc_checked': True,
            })
            (output / 'export-report.json').write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        after = source.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('source changed during export')
        report.update(status='exported', source_size_and_mtime_unchanged=True)
        (output / 'export-report.json').write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipsw', type=Path)
    parser.add_argument('--device-class', default='j171ap')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.ipsw, args.output, args.device_class)
    print(json.dumps({'status': result['status'], 'output': str(args.output.resolve()),
                      'version': result['version'], 'build': result['build']}, ensure_ascii=False))
