#!/usr/bin/env python3
"""Decode exported IM4P kernel/trust inputs for offline porting analysis.

Requires lzfse and the pinned NativePrelink source exported under tools/.
Does not alter code/signatures, connect to a device, or make a bootable image.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'tools' / 'NativePrelink-3380d300'))
import native_prelink as np


def der(data, at=0):
    if at + 2 > len(data):
        raise ValueError('truncated DER')
    tag, size = data[at:at + 2]
    at += 2
    if size & 128:
        count = size & 127
        if not 0 < count <= 4 or at + count > len(data):
            raise ValueError('invalid DER length')
        size = int.from_bytes(data[at:at + count], 'big')
        at += count
    end = at + size
    if end > len(data):
        raise ValueError('DER exceeds input')
    return tag, data[at:end], end


def payload(data):
    tag, sequence, end = der(data)
    if tag != 0x30 or end != len(data):
        raise ValueError('requires an exact IM4P sequence')
    fields, cursor = [], 0
    while cursor < len(sequence):
        tag, blob, cursor = der(sequence, cursor)
        fields.append((tag, blob))
    if len(fields) < 4 or fields[0] != (0x16, b'IM4P') or fields[3][0] != 4:
        raise ValueError('invalid IM4P fields')
    return fields[1][1].decode('ascii'), fields[3][1]


def decode(source, output):
    import lzfse
    output.mkdir(exist_ok=False)
    kind, compressed = payload((source / 'kernelcache.release.ipad7c').read_bytes())
    if kind != 'krnl' or compressed[:4] not in (b'bvx2', b'bvx1', b'bvxn', b'bvx-'):
        raise ValueError('requires an LZFSE kernel payload')
    raw = lzfse.decompress(compressed)
    if raw[:4] == b'\xca\xfe\xba\xbe':
        count = struct.unpack_from('>I', raw, 4)[0]
        if not 0 < count <= 16 or 8 + count * 20 > len(raw):
            raise ValueError('invalid FAT header')
        arches = [struct.unpack_from('>5I', raw, 8 + n * 20) for n in range(count)]
        arm64 = [a for a in arches if a[:2] == (0x100000c, 0)]
        if len(arm64) != 1:
            raise ValueError('requires exactly one ordinary arm64 slice')
        _, _, offset, size, _ = arm64[0]
        if offset + size > len(raw):
            raise ValueError('FAT slice outside input')
        raw = raw[offset:offset + size]
    image = np.macho(raw)
    (output / 'kernelcache.macho').write_bytes(raw)
    info = next(s for s in image['segments'] if s['name'] == '__PRELINK_INFO')
    at = np.backed_offset(image['segments'], info['va'], info['filesize'], len(raw))
    entries = np.unserialize_xml(raw[at:at + info['filesize']])['_PrelinkInfoDictionary']
    inventory = [{key: entry.get(key) for key in (
        'CFBundleIdentifier', 'CFBundleVersion', '_PrelinkExecutableLoadAddr',
        '_PrelinkExecutableSize', 'OSBundleLibraries', 'OSKernelResource')}
        for entry in entries]
    (output / 'kext-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    modules = []
    for name in ('044-17597-018.dmg.trustcache', '044-18090-018.dmg.trustcache'):
        kind, module = payload((source / name).read_bytes())
        version, = struct.unpack_from('<I', module)
        count, = struct.unpack_from('<I', module, 20)
        if kind not in ('trst', 'trcs') or version != 2 or len(module) != 24 + count * 24:
            raise ValueError(f'unexpected trust-cache module: {name}')
        (output / (name + '.bin')).write_bytes(module)
        modules.append(module)
    bundle = struct.pack('<3I', 2, 12, 12 + len(modules[0])) + b''.join(modules)
    (output / 'original-static-system-trust.bundle').write_bytes(bundle)
    versions = [value.decode('ascii', errors='replace') for value in
                re.findall(rb'Darwin Kernel Version[^\x00\r\n]{1,250}', raw)]
    report = dict(kernel_bytes=len(raw), kernel_sha256=hashlib.sha256(raw).hexdigest(),
                  darwin_version_strings=versions, kext_count=len(entries),
                  trust_module_entries=[struct.unpack_from('<I', m, 20)[0] for m in modules],
                  trust_modules_modified=False, device_accessed=False,
                  boot_compatibility_verified=False)
    (output / 'decode-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(decode(args.source, args.output), indent=2))
