#!/usr/bin/env python3
"""Build/sign the standalone owned-BO probe in macOS GitHub Actions only.

No installation, trustcache editing, workflow dispatch or execution occurs here.
The ad-hoc signature still requires separately authorized owner trust at boot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[1]
INPUTS = ('userprobe/nabu_gpu_userprobe.cpp', 'gpu/upstream/Adreno6xx/NativeAdrenoABI.h',
          'gpu/upstream/AdrenoPM4/AdrenoPM4.h', 'gpu/upstream/AdrenoPM4/AdrenoPM4.c',
          'scripts/build-nabu-gpu-userprobe.py')
IDENTIFIER = 'org.hackios.nabu-gpu-userprobe'
TURNIP_IDENTIFIER = 'org.hackios.nabu-turnip'
ENTITLEMENTS = {'com.apple.private.security.no-container': True,
                'com.apple.security.iokit-user-client-class': ['AGXDeviceUserClient'],
                'com.apple.security.ts.opengl-or-metal': True}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_macho(data):
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
        raise ValueError('Probe must be an ordinary ARM64 MH_EXECUTE image')
    commands, extent = struct.unpack_from('<II', data, 16)
    if not commands or extent > len(data) - 32:
        raise ValueError('Invalid probe load-command bounds')
    cursor, ios, signed = 32, False, False
    for _ in range(commands):
        if cursor + 8 > 32 + extent:
            raise ValueError('Truncated probe load command')
        kind, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or size > 32 + extent - cursor:
            raise ValueError('Invalid probe load command')
        if kind == 0x32:
            if size < 24:
                raise ValueError('Truncated probe build-version command')
            platform, minimum = struct.unpack_from('<II', data, cursor + 8)
            ios = platform == 2 and minimum == 0x110000
        if kind == 0x1d:
            if size < 16:
                raise ValueError('Truncated probe signature command')
            offset, length = struct.unpack_from('<II', data, cursor + 8)
            signed = bool(length and offset <= len(data) and length <= len(data) - offset)
        cursor += size
    if cursor != 32 + extent or not ios or not signed:
        raise ValueError('Probe lacks the iOS 17 target or bounded code signature')


def signature_identity(detail):
    match = re.search(r'^CDHash=([0-9a-f]{40})$', detail, re.M)
    if not match or not re.search(r'^Page size=4096$', detail, re.M):
        raise ValueError('Probe signature must expose a CDHash and 4 KiB page size')
    return match[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New private build output directory')
    parser.add_argument('--turnip-library', type=Path,
                        help='Turnip libvulkan_freedreno.dylib built against this ABI; adds the Vulkan known-image stage')
    parser.add_argument('--turnip-headers', type=Path,
                        help='Mesa include directory (vulkan/vulkan_core.h) of the same Turnip build')
    parser.add_argument('--adrenometal', type=Path,
                        help='AdrenoMetal checkout at the pinned revision (NativeTurnipSmoke.h, shaders/)')
    args = parser.parse_args()
    turnip = args.turnip_library is not None
    if turnip != (args.turnip_headers is not None) or turnip != (args.adrenometal is not None):
        raise SystemExit('--turnip-library, --turnip-headers and --adrenometal go together')
    if sys.platform != 'darwin' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Apple probe builds run only in macOS GitHub Actions')
    inputs = {}
    for name in INPUTS:
        source = DEVICE / name
        if not source.is_file() or source.is_symlink():
            raise SystemExit('Missing or linked probe source: ' + name)
        inputs[name] = sha(source.read_bytes())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'result': 'building', 'sources': inputs, 'target': 'arm64-apple-ios17.0',
              'abi_version': 1, 'entitlements': ENTITLEMENTS, 'owner_trust_installed': False,
              'runtime_qualified': False, 'hardware_tested': False, 'rendering_qualified': False,
              'ci': {'run_id': os.environ.get('GITHUB_RUN_ID'),
                     'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
                     'head_sha': os.environ.get('GITHUB_SHA'),
                     'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF')}}
    commands = []

    def run(command, timeout=300):
        command = list(map(str, command))
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        (out / ('command-%02d.log' % len(commands))).write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode:
            raise ValueError('Probe build command %d failed; see its private log' % len(commands))
        return result

    try:
        sdk = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], 30).stdout.strip()
        if not Path(sdk).is_dir():
            raise ValueError('xcrun returned no iPhoneOS SDK directory')
        report['compiler'] = run(['xcrun', '--sdk', 'iphoneos', 'clang++', '--version'], 30).stdout.strip()
        abi = inputs['gpu/upstream/Adreno6xx/NativeAdrenoABI.h']
        base = ['-target', report['target'], '-isysroot', sdk, '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                '-fstack-protector-strong', '-I', DEVICE / 'gpu/upstream/Adreno6xx',
                '-I', DEVICE / 'gpu/upstream/AdrenoPM4']
        pm4 = out / 'AdrenoPM4.o'
        exe = out / 'nabu-gpu-userprobe'
        run(['xcrun', '--sdk', 'iphoneos', 'clang', *base, '-std=c11', '-c',
             DEVICE / 'gpu/upstream/AdrenoPM4/AdrenoPM4.c', '-o', pm4])
        turnip_options = []
        if turnip:
            smoke = args.adrenometal.resolve()
            generated = out / 'turnip-smoke'
            generated.mkdir()
            lines = ['// Generated GLSL compiler output.', '#pragma once', '#include <stdint.h>']
            shaders = sorted((smoke / 'shaders').glob('smoke_*'))
            if [s.name for s in shaders] != ['smoke_fill.comp', 'smoke_triangle.frag', 'smoke_triangle.vert']:
                raise ValueError('Unexpected Turnip smoke shader set')
            for shader in shaders:
                spv = generated / (shader.name + '.spv')
                run(['glslangValidator', '-V', '--target-env', 'vulkan1.1', shader, '-o', spv], 60)
                words = struct.unpack('<%dI' % (spv.stat().st_size // 4), spv.read_bytes())
                lines.append('static const uint32_t kSpv_%s[] = {' % shader.name.replace('.', '_'))
                lines += ['    ' + ', '.join('0x%08x' % w for w in words[i:i + 8]) + ',' for i in range(0, len(words), 8)]
                lines.append('};')
            (generated / 'NativeTurnipShaders.h').write_text('\n'.join(lines) + '\n')
            report['turnip_inputs'] = {'smoke_header_sha256': sha((smoke / 'NativeTurnipSmoke.h').read_bytes()),
                                       'config_header_sha256': sha((smoke / 'NativeAdrenoMetalConfig.h').read_bytes()),
                                       'shaders': {s.name: sha(s.read_bytes()) for s in shaders}}
            # A640: no recorded A740 replay; the smoke keeps its own TU_DEBUG default.
            turnip_options = ['-DNABU_USERPROBE_TURNIP=1', '-DNATIVE_ADRENO_A740_REPLAY=0', '-Wno-unused-function',
                              '-Wno-missing-field-initializers', '-I', smoke, '-I', args.turnip_headers.resolve(),
                              '-I', generated]
        run(['xcrun', '--sdk', 'iphoneos', 'clang++', *base, '-std=c++17', *turnip_options,
             '-DNABU_USERPROBE_ABI_SHA256="' + abi + '"', DEVICE / INPUTS[0], pm4,
             '-framework', 'CoreFoundation', '-o', exe])
        entitlements = out / 'entitlements.plist'
        entitlements.write_bytes(plistlib.dumps(ENTITLEMENTS, fmt=plistlib.FMT_XML))
        run(['codesign', '--force', '--sign', '-', '--pagesize', '4096', '--identifier', IDENTIFIER,
             '--entitlements', entitlements, exe], 30)
        run(['codesign', '--verify', '--strict', exe], 30)
        detail = run(['codesign', '--display', '--verbose=4', exe], 30).stderr
        actual = run(['codesign', '--display', '--entitlements', ':-', exe], 30).stdout
        if plistlib.loads(actual.encode()) != ENTITLEMENTS:
            raise ValueError('Signed probe entitlements differ from the requested set')
        binary = exe.read_bytes()
        validate_macho(binary)
        if abi.encode() not in binary:
            raise ValueError('Probe binary lacks its canonical ABI source identity')
        if any(sha((DEVICE / name).read_bytes()) != digest for name, digest in inputs.items()):
            raise ValueError('Probe source changed during the build')
        report.update(result='signed_not_run', executable=exe.name, bytes=len(binary),
                      sha256=sha(binary), cdhash=signature_identity(detail), signature_page_bytes=4096)
        if turnip:
            library = out / 'libvulkan_freedreno.dylib'
            library.write_bytes(args.turnip_library.resolve().read_bytes())
            run(['strip', '-x', library], 120)
            run(['codesign', '--force', '--sign', '-', '--pagesize', '4096', '--identifier', TURNIP_IDENTIFIER,
                 library], 120)
            run(['codesign', '--verify', '--strict', library], 120)
            turnip_detail = run(['codesign', '--display', '--verbose=4', library], 60).stderr
            report['turnip'] = {'library': library.name, 'source_sha256': sha(args.turnip_library.read_bytes()),
                                'bytes': library.stat().st_size, 'sha256': sha(library.read_bytes()),
                                'cdhash': signature_identity(turnip_detail), 'identifier': TURNIP_IDENTIFIER}
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report.update(result='failed', error=str(error))
        raise
    finally:
        report['commands'] = commands
        (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
