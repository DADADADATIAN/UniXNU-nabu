#!/usr/bin/env python3
"""Build modern read-only VirtIO MMIO against the 21H16 storage class."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess

from nabu_storage_bindings import BINDINGS

spec = importlib.util.spec_from_file_location(
    'platform_builder', Path(__file__).with_name('build-nabu-platform.py'))
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def main():
    root = Path(__file__).resolve().parents[1]
    record_path = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    record = json.loads(record_path.read_text().strip().rstrip(','))
    source = root / 'drivers/NativeVirtioBlock/NativeVirtioBlock.cpp'
    out = root / 'build/native-virtio-block'
    out.mkdir(parents=True, exist_ok=True)
    obj = out / 'NativeVirtioBlock.o'
    command = platform.compile_command(record, source, obj)
    command += ['-I', str(root / 'build/storage-abi/include'),
                '-I', str(root / '.cache/xnu-work/osfmk')]
    verified = os.environ.get('XNU_OWNER_ROOT_TRUST') == '1'
    multi_policy = bool(os.environ.get('UNIXNU_OWNER_POLICY_SYSTEMOS'))
    if verified:
        # The optional UFS backend is absent from this QEMU profile. Kernel
        # linking still requires its weak import unless the call is compiled out.
        text = source.read_text(encoding='utf-8').replace(
            '      if (!block) {\n        if (native_ufs_block_authenticates) {',
            '      if (!block) {\n#if XNU_NATIVE_UFS\n        if (native_ufs_block_authenticates) {')
        text = text.replace('        continue;\n      }\n      authenticated = block->',
                            '#endif\n        continue;\n      }\n      authenticated = block->')
        patched = out / 'NativeVirtioBlock.cpp'
        patched.write_text(text, encoding='utf-8')
        command = platform.compile_command(record, patched, obj)
        command += ['-I', str(root / 'build/storage-abi/include'),
                    '-I', str(root / '.cache/xnu-work/osfmk'),
                    '-I', str(source.parent),
                    '-DNATIVE_VERIFIED_BLOCK=1',
                    '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=' + ('1' if multi_policy else '0'),
                    '-DXNU_NATIVE_UFS=' + os.environ.get('XNU_NATIVE_UFS', '0'),
                    '-I', str(root / 'kits/VerifiedRoot/include')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    subprocess.run(command, cwd=record['directory'], check=True)
    assembly = out / 'original-bindings.S'
    assembly.write_text(''.join(f'.globl {name}\n.set {name}, {value:#x}\n'
                               for name, value in BINDINGS.items()))
    bindings_obj = out / 'original-bindings.o'
    subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                    str(assembly), '-o', str(bindings_obj)], check=True)
    archive = out / 'libNativeVirtioBlock.a'
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj), str(bindings_obj)], check=True)
    (out / 'bindings.json').write_text(json.dumps({
        'original_build': '21H16', 'slide': -0x1360000,
        'bindings': {name: hex(value) for name, value in BINDINGS.items()},
        'compiled_object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'transport': 'modern-mmio', 'read_only': True,
        'verified_root_enabled': verified, 'runtime_qualified': False,
        'multi_policy_enabled': multi_policy,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
