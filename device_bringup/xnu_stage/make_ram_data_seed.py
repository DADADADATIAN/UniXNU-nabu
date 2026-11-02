#!/usr/bin/env python3
"""Create the volatile APFS Data seed used by the nabu RAM Data experiment.

The image is a deliberately empty APFS container with one volume.  The guest
launchd/dirs_cleaner path is expected to create the directories it needs; this
script does not copy host files or claim a provisioned iOS Data volume.
Requires Linux apfsprogs (mkapfs/apfsutil) and no macOS hdiutil.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

VOLUME_UUID = '0A5EED00-0000-4000-8000-000000000001'
CONTAINER_UUID = '0A5EED00-0000-4000-8000-000000000000'
SIZE_MIB = 32


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--size-mib', type=int, default=SIZE_MIB)
    parser.add_argument('--volume-uuid', default=VOLUME_UUID)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit('Refuse to overwrite an existing seed: ' + str(output))
    if args.size_mib < 16 or args.size_mib > 256:
        raise SystemExit('Seed size must be between 16 and 256 MiB (DarwinBoot RAMDisk limit)')
    for tool in ('mkapfs', 'apfsutil'):
        if not shutil.which(tool):
            raise SystemExit('Missing APFS tool: ' + tool)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('wb') as image:
        image.truncate(args.size_mib * 1024 * 1024)
    subprocess.run(['mkapfs', '-L', 'OwnerData', '-U', CONTAINER_UUID,
                    '-u', args.volume_uuid, str(output)], check=True)
    data = output.read_bytes()
    if len(data) != args.size_mib * 1024 * 1024 or data[32:36] != b'NXSB':
        raise SystemExit('mkapfs did not produce the requested raw APFS container')
    info = subprocess.run(['apfsutil', str(output)], check=True,
                          capture_output=True, text=True).stdout
    if args.volume_uuid.upper() not in info.upper():
        raise SystemExit('apfsutil did not report the expected volume UUID')
    report = {
        'format': 'empty APFS container for volatile RAM Data',
        'image': str(output),
        'image_bytes': len(data),
        'image_sha256': sha256(output),
        'container_uuid': CONTAINER_UUID,
        'volume_uuid': args.volume_uuid.upper(),
        'size_mib': args.size_mib,
        'initial_var_files': 0,
        'initial_directories': [],
        'guest_mutable': True,
        'tool': 'apfsprogs mkapfs/apfsutil',
        'tool_version': subprocess.run(['dpkg-query', '-W', '-f=${Version}', 'apfsprogs'],
                                       capture_output=True, text=True).stdout.strip(),
        'macos_hdiutil_used': False,
        'production_storage_qualified': False,
        'note': 'Empty seed; launchd/dirs_cleaner must create the runtime directories. '
                'Record the first real guest write and the next service failure.',
    }
    sidecar = output.with_suffix(output.suffix + '.json')
    sidecar.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()