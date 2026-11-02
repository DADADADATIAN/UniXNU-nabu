#!/usr/bin/env python3
"""Actions builder and candidate checker for the opt-in nabu read-only LUN."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import nabu_ufs_readonly as source

spec = importlib.util.spec_from_file_location('nabu_ufs_base', Path(__file__).with_name('build-nabu-ufs.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
FLAGS = ['-DNABU_UFS_READONLY=1', '-DNATIVE_VERIFIED_BLOCK=0']


def check_candidate(obj, candidate, plan):
    report = base.bindings.check_candidate(obj, candidate, plan)
    required = {'__ZN9NativeUfs5startEP9IOService', '__ZN9NativeUfs10gMetaClassE',
                '_native_ufs_readonly_abi', '_native_ufs_readonly_starts',
                '_native_ufs_readonly_requested', '_native_ufs_readonly_stage',
                '_native_ufs_lun_blocks', '_native_ufs_lba0_crc32', '_native_ufs_readonly_failure'}
    if not required <= candidate.names.keys():
        raise ValueError('Final candidate lacks read-only UFS symbols: ' + ', '.join(sorted(required - candidate.names.keys())))
    if struct.unpack('<I', candidate.read(candidate.names['_native_ufs_readonly_abi'], 4))[0] != 1:
        raise ValueError('Wrong read-only UFS ABI marker')
    if any(name == '_boot_progress_poll' and kind == 1 for name, _, kind in obj.symbols):
        raise ValueError('Read-only UFS must not import disabled BootProgress')
    forbidden = {'_native_ufs_block_authenticates', '_vr_open', '_vr_verify_block',
                 '_verified_root_manifest', '_verified_root_key'}
    if any(name in forbidden for name, _, _ in obj.symbols):
        raise ValueError('Raw UFS object contains an unintended owner-verifier dependency')
    return dict(report, readonly_abi=1, linked_symbols=sorted(required),
                linked_block_slots_checked=base.check_linked_block_dispatch(obj, candidate),
                runtime_qualified=False)


def build():
    root = Path(__file__).resolve().parents[1]
    device = Path(os.environ['UNIXNU_DEVICE']).resolve()
    if any(os.environ.get(name, '0') != '0' for name in ('XNU_NATIVE_VIRTIO_BLOCK', 'XNU_OWNER_ROOT_TRUST')):
        raise SystemExit('Raw read-only UFS does not supply shared bindings or a verified system root')
    recipe = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe.read_bytes()
    record = json.loads(recipe_bytes.decode().strip().rstrip(','))
    headers = root / 'build/storage-abi/include'
    if not (headers / 'IOKit/storage/IOBlockStorageDevice.h').is_file():
        raise SystemExit('Missing actual IOStorageFamily headers')
    out = root / 'build/native-ufs'
    if out.exists():
        raise SystemExit('Refuse an existing UFS output; use a fresh build')
    tree = out / 'source'
    source.prepare((root / 'drivers/NativeUfs').resolve(), tree, device)
    cpp, obj = tree / 'NativeUfs.cpp', out / 'NativeUfs.o'
    command = base.platform.compile_command(record, cpp, obj)
    command += ['-I', str(headers), '-I', str(root / '.cache/xnu-work/osfmk'), *FLAGS]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if recipe.read_bytes() != recipe_bytes:
        raise SystemExit('UFS compilation changed its reference recipe')
    if result.returncode:
        raise SystemExit(result.stderr.decode(errors='replace')[-4000:])
    base.platform.check_object(obj.read_bytes())
    base.bindings.qualify_object(base.bindings.MachO(obj))
    subprocess.run([sys.executable, str(Path(base.bindings.__file__)), '--object', str(obj),
                    '--output-dir', str(out)], check=True)
    (out / 'build-report.json').write_text(json.dumps({
        'source_commit': base.prepare.PINNED_COMMIT, 'compiled': True, 'linked': False,
        'source_files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(tree.iterdir()) if p.suffix in ('.cpp', '.h')},
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
        'archive_sha256': hashlib.sha256((out / 'libNativeUfs.a').read_bytes()).hexdigest(),
        'source_flags': FLAGS, 'passive_only': False, 'read_only': True,
        'hardware_access_opt_in': 'native-ufs-readonly=1 and exact resource provider',
        'verified_root_enabled': False, 'runtime_qualified': False, 'hardware_tested': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-candidate', type=Path)
    parser.add_argument('--object', type=Path)
    parser.add_argument('--prelink-report', type=Path)
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    if args.check_candidate:
        if not all((args.object, args.prelink_report, args.output_dir)):
            parser.error('Candidate checking requires object, prelink report and output directory')
        report = check_candidate(base.bindings.MachO(args.object), base.bindings.MachO(args.check_candidate),
                                 json.loads(args.prelink_report.read_text()))
        (args.output_dir / 'candidate-bindings.json').write_text(json.dumps(report, indent=2) + '\n')
    elif any((args.object, args.prelink_report, args.output_dir)):
        parser.error('Object/report/output require --check-candidate')
    else:
        build()
