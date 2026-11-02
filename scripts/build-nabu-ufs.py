#!/usr/bin/env python3
"""Build the passive SM8150 UFS candidate using Actions' current XNU recipe.

The captured-line preparation and ABI helpers are byte-identical payload copies;
tools/test_nabu_ufs_source_ci.py checks that they cannot silently drift apart.
This builder deliberately cannot enable controller access via its environment.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys

import native_ufs_bindings as bindings
import prepare_nabu_ufs_source as prepare

spec = importlib.util.spec_from_file_location(
    'nabu_ufs_platform', Path(__file__).with_name('build-nabu-platform.py'))
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)

PASSIVE_FIELDS = '''volatile uint32_t native_ufs_passive_abi = 1;
volatile uint32_t native_ufs_passive_starts = 0;
volatile uint32_t native_ufs_passive_probe = 0;
volatile uint32_t native_ufs_passive_root = 0;
volatile uint32_t native_ufs_passive_blocked = 0;
'''
PASSIVE_START = '''#if !defined(NABU_UFS_PASSIVE_ONLY) || NABU_UFS_PASSIVE_ONLY != 1
#error "This prepared artifact requires passive-only UFS compilation"
#endif
#if NABU_UFS_PASSIVE_ONLY
  (void)provider;
  unsigned probe = 0, rootMode = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  PE_parse_boot_argn ("native-ufs-root", &rootMode, sizeof (rootMode));
  native_ufs_passive_starts = native_ufs_passive_starts + 1;
  native_ufs_passive_probe = probe;
  native_ufs_passive_root = rootMode;
  native_ufs_probe_requested = probe != 0;
  if (probe || rootMode) native_ufs_passive_blocked = native_ufs_passive_blocked + 1;
  IOLog ("NABU UFS PASSIVE v1 start=%u probe=%u root=%u mmio=blocked\\n",
         native_ufs_passive_starts, probe, rootMode);
  return false;
#else
'''


def passive_source(text):
    """Fail closed on source drift; do not execute the inherited diagnostic modes."""
    start = 'bool NativeUfs::start (IOService *provider)\n{\n'
    end = '\n}\n\n// Boot the root image\'s windows as block devices.'
    fields = 'volatile uint32_t native_ufs_probe_calls = 0;'
    if any(text.count(marker) != 1 for marker in (start, end, fields)):
        raise ValueError('Expected the pinned NativeUfs start and counter anchors')
    if '#if NABU_UFS_PASSIVE_ONLY' in text:
        raise ValueError('Refuse already transformed UFS source')
    text = text.replace(fields, PASSIVE_FIELDS + fields, 1)
    text = text.replace(start, start + PASSIVE_START, 1)
    return text.replace(end, '\n#endif' + end, 1)


def source_flags():
    # No caller-selectable active mode in this milestone. Keep unused verifier
    # and BootProgress out of the archive's real dependency closure.
    return ['-DNABU_UFS_PASSIVE_ONLY=1', '-DNATIVE_VERIFIED_BLOCK=0']


def check_passive_candidate(obj, candidate, plan):
    report = bindings.check_candidate(obj, candidate, plan)
    required = {'__ZN9NativeUfs5startEP9IOService', '__ZN9NativeUfs10gMetaClassE',
                '_native_ufs_passive_abi', '_native_ufs_passive_starts',
                '_native_ufs_passive_probe', '_native_ufs_passive_root',
                '_native_ufs_passive_blocked'}
    if not required <= candidate.names.keys():
        raise ValueError('Final candidate lacks linked passive UFS symbols: ' +
                         ', '.join(sorted(required - candidate.names.keys())))
    if struct.unpack('<I', candidate.read(candidate.names['_native_ufs_passive_abi'], 4))[0] != 1:
        raise ValueError('Final candidate has the wrong passive UFS ABI marker')
    if any(name == '_boot_progress_poll' and kind == 1 for name, _, kind in obj.symbols):
        raise ValueError('Passive UFS must not import the disabled BootProgress feature')
    slots = check_linked_block_dispatch(obj, candidate)
    return dict(report, passive_abi=1, linked_symbols=sorted(required),
                linked_block_slots_checked=slots, runtime_qualified=False)


def check_linked_block_dispatch(obj, candidate):
    """The original parent's vtable alone does not qualify the linked subclass."""
    vtable = candidate.names.get('__ZTV14NativeUfsBlock')
    if vtable is None:
        raise ValueError('Final candidate lacks the NativeUfsBlock vtable')
    methods = bindings.qualify_object(obj)
    for index, name in enumerate(methods):
        expected = candidate.names.get(name, bindings.BINDINGS.get(name))
        actual = struct.unpack('<Q', candidate.read(vtable + 16 + index * 8, 8))[0]
        if expected is None or actual != expected:
            raise ValueError(f'Linked UFS subclass dispatch mismatch at slot {index}: {name}')
    return len(methods)


def main():
    root = Path(__file__).resolve().parents[1]
    device = Path(os.environ['UNIXNU_DEVICE']).resolve()
    if os.environ.get('XNU_NATIVE_VIRTIO_BLOCK', '0') != '0':
        raise SystemExit('Combined UFS/VirtIO needs shared-parent binding deduplication first')
    if os.environ.get('XNU_OWNER_ROOT_TRUST', '0') != '0':
        raise SystemExit('This passive profile does not build an owner-verified UFS backend')
    recipe = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    headers = root / 'build/storage-abi/include'
    if not (headers / 'IOKit/storage/IOBlockStorageDevice.h').is_file():
        raise SystemExit('The enabled UFS class requires the real prepared IOStorageFamily headers')
    out = root / 'build/native-ufs'
    if out.exists():
        raise SystemExit('Refuse an existing UFS output; use a fresh build tree')
    source = out / 'source'
    patch = device / 'patches/nabu-nativeufs-board.patch'
    prepare.main(['--source', str((root / 'drivers/NativeUfs').resolve()),
                  '--output-dir', str(source), '--patch', str(patch)])
    cpp = source / 'NativeUfs.cpp'
    cpp.write_text(passive_source(cpp.read_text(encoding='utf-8')), encoding='utf-8')
    obj = out / 'NativeUfs.o'
    command = platform.compile_command(record, cpp, obj)
    command += ['-I', str(headers), '-I', str(root / '.cache/xnu-work/osfmk'), *source_flags()]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if recipe.read_bytes() != recipe_bytes:
        raise SystemExit('UFS compilation modified the original XNU recipe')
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    platform.check_object(obj.read_bytes())
    bindings.qualify_object(bindings.MachO(obj))
    subprocess.run([sys.executable, str(Path(bindings.__file__)), '--object', str(obj),
                    '--output-dir', str(out)], check=True)
    archive = out / 'libNativeUfs.a'
    (out / 'build-report.json').write_text(json.dumps({
        'source_commit': prepare.PINNED_COMMIT,
        'source_files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(source.iterdir()) if p.suffix in ('.cpp', '.h')},
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
        'source_flags': source_flags(),
        'compiled': True, 'linked': False, 'passive_only': True,
        'verified_root_enabled': False, 'runtime_qualified': False, 'hardware_tested': False,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-candidate', type=Path)
    parser.add_argument('--object', type=Path)
    parser.add_argument('--prelink-report', type=Path)
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    if args.check_candidate:
        if not all((args.object, args.prelink_report, args.output_dir)):
            parser.error('Candidate check requires object, prelink report and output directory')
        report = check_passive_candidate(bindings.MachO(args.object), bindings.MachO(args.check_candidate),
                                         json.loads(args.prelink_report.read_text(encoding='utf-8')))
        (args.output_dir / 'candidate-bindings.json').write_text(json.dumps(report, indent=2) + '\n',
                                                               encoding='utf-8')
    else:
        if any((args.object, args.prelink_report, args.output_dir)):
            parser.error('Object/report/output are only valid with --check-candidate')
        main()
