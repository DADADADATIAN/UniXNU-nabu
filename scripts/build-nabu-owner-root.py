#!/usr/bin/env python3
"""Build the VerifiedRoot XNU archive from a prepared owner policy bundle."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import uuid


HEADER = struct.Struct('<8s4I2Q16s32s32s32sQ')


def read_policy(policy_dir):
    manifest_path = policy_dir / 'manifest.bin'
    key_path = policy_dir / 'trusted-key.bin'
    manifest = manifest_path.read_bytes()
    key = key_path.read_bytes()
    (magic, version, header_size, block_bytes, reserved, image_bytes, block_count,
     volume_uuid, image_digest, hash_digest, key_digest, generation) = HEADER.unpack_from(manifest)
    # The private input is pinned by the workflow. Signature, anchor and block
    # validation belong to the real vr_open/vr_verify_block execution in XNU.
    return {
        'manifest': manifest_path,
        'trusted_key': key_path,
        'manifest_bytes': len(manifest),
        'trusted_key_bytes': len(key),
        'image_bytes': image_bytes,
        'block_count': block_count,
        'volume_uuid': str(uuid.UUID(bytes=volume_uuid)).upper(),
        'generation': generation,
    }


def policy_assembly(policy, systemos=None):
    text = (
        '.section __DATA_CONST,__const\n'
        '.balign 8\n.globl _verified_root_manifest\n'
        '_verified_root_manifest:\n'
        f'.incbin "{policy["manifest"].as_posix()}"\n'
        '.balign 8\n.globl _verified_root_manifest_bytes\n'
        f'_verified_root_manifest_bytes:\n.quad {policy["manifest_bytes"]}\n'
        '.balign 8\n.globl _verified_root_key\n'
        '_verified_root_key:\n'
        f'.incbin "{policy["trusted_key"].as_posix()}"\n')
    if systemos:
        text += (
            '.balign 8\n.globl _verified_root_manifest_systemos\n'
            '_verified_root_manifest_systemos:\n'
            f'.incbin "{systemos["manifest"].as_posix()}"\n'
            '.balign 8\n.globl _verified_root_manifest_systemos_bytes\n'
            f'_verified_root_manifest_systemos_bytes:\n.quad {systemos["manifest_bytes"]}\n'
            '.balign 8\n.globl _verified_root_policies\n'
            '_verified_root_policies:\n'
            f'.quad _verified_root_manifest, {policy["manifest_bytes"]}\n'
            f'.quad _verified_root_manifest_systemos, {systemos["manifest_bytes"]}\n'
            '.balign 8\n.globl _verified_root_policy_count\n'
            '_verified_root_policy_count:\n.quad 2\n')
    return text


def main():
    root = Path(__file__).resolve().parents[1]
    policy_dir = Path(os.environ['UNIXNU_OWNER_POLICY']).resolve()
    policy = read_policy(policy_dir)
    systemos_dir = os.environ.get('UNIXNU_OWNER_POLICY_SYSTEMOS')
    systemos = read_policy(Path(systemos_dir).resolve()) if systemos_dir else None
    if systemos and policy['trusted_key'].read_bytes() != systemos['trusted_key'].read_bytes():
        raise SystemExit('OS and SystemOS policies must use the same owner trust anchor')

    recipe_path = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/bsd_init.o.json'
    record = json.loads(recipe_path.read_text().strip().rstrip(','))
    script_path = Path(__file__).resolve()
    platform_path = script_path.with_name('build-nabu-platform.py')
    spec = importlib.util.spec_from_file_location('nabu_platform_builder', platform_path)
    platform = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(platform)

    verified_root = root / 'kits/VerifiedRoot'
    include = verified_root / 'include'
    sources = [verified_root / 'src/verified_root.c',
               verified_root / 'adapters/xnu_crypto.c']
    out = root / 'build/verified-root-xnu'
    out.mkdir(parents=True, exist_ok=True)
    archive = out / 'libVerifiedRootProbe.a'
    if archive.exists():
        raise SystemExit('Refuse to reuse an existing VerifiedRoot archive; use a fresh build root')

    commands = []
    objects = []
    for source in sources:
        obj = out / (source.stem + '.o')
        command = platform.compile_command(record, source, obj)
        command += ['-I', str(include), '-I', str(root / '.cache/xnu-work/osfmk')]
        subprocess.run(command, cwd=record['directory'], check=True)
        commands.append(command)
        objects.append(obj)

    assembly = out / 'inputs.S'
    assembly.write_text(policy_assembly(policy, systemos), encoding='utf-8')
    inputs_obj = out / 'inputs.o'
    assembly_command = ['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                        str(assembly), '-o', str(inputs_obj)]
    subprocess.run(assembly_command, check=True)
    commands.append(assembly_command)
    objects.append(inputs_obj)

    archive_command = ['xcrun', 'ar', 'rcs', str(archive), *(str(obj) for obj in objects)]
    subprocess.run(archive_command, check=True)
    commands.append(archive_command)
    (out / 'compile-command.json').write_text(
        json.dumps(commands, indent=2) + '\n', encoding='utf-8')
    report = {
        'archive': archive.name,
        'sources': ['VerifiedRoot/src/verified_root.c', 'VerifiedRoot/adapters/xnu_crypto.c',
                    'inputs.S'],
        'policy': {
            'format': 'VROOT01 v1',
            'image_bytes': policy['image_bytes'],
            'block_count': policy['block_count'],
            'volume_uuid': policy['volume_uuid'],
            'generation': policy['generation'],
        },
        'systemos_policy': None if not systemos else {
            'image_bytes': systemos['image_bytes'],
            'block_count': systemos['block_count'],
            'volume_uuid': systemos['volume_uuid'],
            'generation': systemos['generation'],
        },
        'architecture': 'arm64',
        'deployment': 'iOS 17.0',
        'runtime_qualified': False,
        'boot_root_authenticated': False,
    }
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n',
                                           encoding='utf-8')


if __name__ == '__main__':
    main()
