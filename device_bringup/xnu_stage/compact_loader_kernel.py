#!/usr/bin/env python3
"""Pack nonzero prelink pages for DarwinBoot without changing loaded memory.

The outer Mach-O describes the compact file. The original kernel Mach-O header
is retained inside its __TEXT segment, so XNU sees its original segment layout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

PAGE = 4096
SPARSE = {'__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PLK_DATA_CONST', '__PRELINK_DATA'}


def compact(data):
    original, pieces, commands = [], [], []
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        command = bytearray(data[at:at + size])
        if cmd == 0x19:
            name, va, extent, offset, backed, maxprot, prot, _, _ = struct.unpack_from('<16s4Q4I', command, 8)
            original.append((va, extent, offset, backed))
            if extent and name.rstrip(b'\0').decode() in SPARSE:
                pages = [i for i in range(0, backed, PAGE)
                         if data[offset + i:offset + min(i + PAGE, backed)].strip(b'\0')]
                groups = []
                for page in pages:
                    if groups and groups[-1][1] == page:
                        groups[-1][1] = min(page + PAGE, backed)
                    else:
                        groups.append([page, min(page + PAGE, backed)])
                for begin, end in groups:
                    group = bytearray(struct.pack('<II16s4Q4I', 0x19, 72,
                        f'__P{len(pieces)}'.encode(), va + begin, end - begin, 0,
                        end - begin, maxprot, prot, 0, 0))
                    pieces.append((group, offset + begin, data[offset + begin:offset + end]))
            elif extent:
                pieces.append((command, offset, data[offset:offset + backed]))
        else:
            commands.append(command)
        at += size
    base = min(va for va, extent, _, _ in original if extent)
    end = max(va + extent for va, extent, _, _ in original)
    if min(struct.unpack_from('<Q', cmd, 24)[0] for cmd, _, _ in pieces) != base:
        anchor = bytearray(struct.pack('<II16s4Q4I', 0x19, 72, b'__ANCHOR', base, PAGE, 0, 0, 1, 1, 0, 0))
        pieces.append((anchor, 0, b''))
    cursor = (32 + sum(len(cmd) for cmd, _, _ in pieces) + sum(map(len, commands)) + PAGE - 1) & -PAGE
    output = bytearray(cursor)
    mappings = []
    for command, old_offset, blob in pieces:
        struct.pack_into('<Q', command, 40, cursor)
        mappings.append((old_offset, len(blob), cursor))
        delta = cursor - old_offset
        for i in range(struct.unpack_from('<I', command, 64)[0]):
            pos = 72 + i * 80 + 48
            value = struct.unpack_from('<I', command, pos)[0]
            if value:
                struct.pack_into('<I', command, pos, value + delta)
        output.extend(blob)
        output.extend(bytes(-len(output) % PAGE))
        cursor = len(output)

    def file_offset(value):
        return next(new + value - old for old, size, new in mappings if old <= value < old + size)

    for command in commands:
        cmd = struct.unpack_from('<I', command)[0]
        offsets = {2: (8, 16), 0xb: (32, 40, 48, 56, 64, 72), 0x26: (8,)}.get(cmd, ())
        for pos in offsets:
            value = struct.unpack_from('<I', command, pos)[0]
            if value:
                struct.pack_into('<I', command, pos, file_offset(value))
    all_commands = [cmd for cmd, _, _ in pieces] + commands
    output[:32] = data[:32]
    struct.pack_into('<II', output, 16, len(all_commands), sum(map(len, all_commands)))
    encoded = b''.join(all_commands)
    output[32:32 + len(encoded)] = encoded

    before, after = bytearray(end - base), bytearray(end - base)
    for va, _, offset, backed in original:
        before[va - base:va - base + backed] = data[offset:offset + backed]
    for command, _, _ in pieces:
        va, _, offset, backed = struct.unpack_from('<4Q', command, 24)
        after[va - base:va - base + backed] = output[offset:offset + backed]
    if before != after:
        raise ValueError('Packing changed the kernel memory image')
    return bytes(output), len(pieces), end - base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--prelink-report', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    data = args.kernel.read_bytes()
    packed, segments, memory_bytes = compact(data)
    (args.output_dir / 'kernel.macho').write_bytes(packed)
    report = json.loads(args.prelink_report.read_text(encoding='utf-8'))
    source_sha = report['candidate_sha256']
    report.update(candidate_sha256=hashlib.sha256(packed).hexdigest(), candidate_bytes=len(packed),
                  loader_container={'source_candidate_sha256': source_sha,
                                    'loaded_memory_identical': True, 'segments': segments,
                                    'memory_bytes': memory_bytes, 'original_kernel_header_retained': True})
    (args.output_dir / 'kernel.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'Packed {len(data)} -> {len(packed)} bytes; {segments} segments; loaded memory unchanged')


if __name__ == '__main__':
    main()
