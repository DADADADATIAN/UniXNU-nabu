#!/usr/bin/env python3
"""Build the volatile NativeRamBlock transport against the 21H16 storage ABI.

The archive intentionally contains only NativeRamBlock.o.  The absolute
IOStorageFamily aliases are provided once by libNativeVirtioBlock.a; the kernel
linker selects this object directly when both transports are enabled.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from nabu_storage_bindings import BINDINGS
from nabu_ram_source import volatile_source

spec_path = Path(__file__).with_name('build-nabu-platform.py')
import importlib.util

spec = importlib.util.spec_from_file_location('nabu_platform_builder', spec_path)
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def main():
    root = Path(__file__).resolve().parents[1]
    recipe_path = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe_path.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    headers = root / 'build/storage-abi/include'
    out = root / 'build/native-ram-block'
    original = root / 'drivers/NativeRamBlock/NativeRamBlock.cpp'
    if not original.is_file():
        raise SystemExit('NativeRamBlock source is missing')
    if not (headers / 'IOKit/storage/IOBlockStorageDevice.h').is_file():
        raise SystemExit('The RAM block class requires the prepared IOStorageFamily headers')
    if out.exists():
        raise SystemExit('Refuse to reuse an existing NativeRamBlock output; use a fresh build root')
    out.mkdir(parents=True)
    persistent_store = os.environ.get('XNU_NATIVE_UFS') == '1'
    userprobe = os.environ.get('NABU_GPU_USERPROBE') == '1'
    if userprobe and (os.environ.get('NABU_GPU_METAL') != '1' or not persistent_store or
                      os.environ.get('XNU_OWNER_DATA_MOUNT') != '1'):
        raise SystemExit('GPU userprobe boot support requires the Metal/UFS/Data profile')
    source = out / 'NativeRamBlock.cpp'
    text = original.read_text(encoding='utf-8')
    support = None
    if userprobe:
        from nabu_gpu_userprobe_source import ram_source as gpu_userprobe_source
        header = Path(os.environ['UNIXNU_DEVICE']) / 'platform/NabuGpuUserprobeAddon.h'
        header_data = header.read_bytes()
        (out / header.name).write_bytes(header_data)
        text = gpu_userprobe_source(text)
        support = {'header_sha256': hashlib.sha256(header_data).hexdigest(),
                   'generator_sha256': hashlib.sha256(Path(__file__).with_name(
                       'nabu_gpu_userprobe_source.py').read_bytes()).hexdigest()}
    source.write_text(text if persistent_store else volatile_source(text), encoding='utf-8')
    obj = out / 'NativeRamBlock.o'
    command = platform.compile_command(record, source, obj)
    command += ['-I', str(headers), '-I', str(root / '.cache/xnu-work/osfmk'),
                '-I', str(original.parent), '-DXNU_NATIVE_RAM_BLOCK=1']
    if not persistent_store:
        command.append('-DNABU_RAM_PERSISTENCE=0')
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    data = obj.read_bytes()
    platform.check_object(data)
    # The compiled object must be a normal ARM64 relocatable with the expected
    # original IOStorageFamily undefined imports.
    archive = out / 'libNativeRamBlock.a'
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj)], check=True)
    (out / 'bindings.json').write_text(json.dumps({
        'original_build': '21H16', 'slide': -0x1360000,
        'bindings': {name: hex(value) for name, value in BINDINGS.items()},
        'compiled_object_sha256': hashlib.sha256(data).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'transport': 'ram-seed', 'read_only': False,
        'bindings_provider': 'libNativeVirtioBlock.a/original-bindings.o',
        'runtime_qualified': False,
    }, indent=2) + '\n')
    (out / 'build-report.json').write_text(json.dumps({
        'source': 'drivers/NativeRamBlock/NativeRamBlock.cpp',
        'actual_source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'optional_ufs_persistence': persistent_store,
        'gpu_userprobe_addon': support,
        'object_sha256': hashlib.sha256(data).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'compiled': True, 'linked': False, 'hardware_tested': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
