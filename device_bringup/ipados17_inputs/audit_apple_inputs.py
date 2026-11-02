#!/usr/bin/env python3
"""Check supplied Apple Mach-O/cache structure, code hashes and original trust membership.

This does not validate the Apple certificate chain, kernel ABI, or bootability.
No image is modified. Format offsets come from the pinned Apple dyld C header.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def require(value, message):
    if not value:
        raise ValueError(message)


def trust_entries(path):
    raw = path.read_bytes()
    require(len(raw) >= 24, 'truncated trust module')
    version, = struct.unpack_from('<I', raw)
    count, = struct.unpack_from('<I', raw, 20)
    require(version == 2 and len(raw) == 24 + count * 24, 'invalid trust module')
    return {(raw[at:at + 20], raw[at + 20]) for at in range(24, len(raw), 24)}


def code_directories(path, offset, size, trust):
    length = path.stat().st_size
    require(0 < size <= 16 << 20 and offset + size <= length, 'invalid signature extent')
    with path.open('rb') as stream:
        stream.seek(offset)
        blob = stream.read(size)
        magic, total, count = struct.unpack_from('>3I', blob)
        require(magic == 0xfade0cc0 and 12 + count * 8 <= total <= size, 'invalid signature superblob')
        result = []
        for index in range(count):
            slot, at = struct.unpack_from('>2I', blob, 12 + index * 8)
            require(at + 8 <= total, 'signature index outside container')
            magic, extent = struct.unpack_from('>2I', blob, at)
            require(at + extent <= total, 'signature blob outside container')
            if magic != 0xfade0c02:
                continue
            cd = blob[at:at + extent]
            require(len(cd) >= 44, 'truncated CodeDirectory')
            version, flags, hashes, ident, special, slots, limit = struct.unpack_from('>7I', cd, 8)
            hash_size, hash_type, platform, shift = struct.unpack_from('4B', cd, 36)
            if version >= 0x20300:
                require(len(cd) >= 64, 'truncated 64-bit code limit')
                limit = struct.unpack_from('>Q', cd, 56)[0] or limit
            if version >= 0x20100:
                require(len(cd) >= 48 and struct.unpack_from('>I', cd, 44)[0] == 0,
                        'scatter CodeDirectory is unsupported')
            require(hash_type == 2 and hash_size == 32 and shift in (12, 14),
                    'unsupported CodeDirectory algorithm/page size')
            block = 1 << shift
            require(limit == offset and slots == (limit + block - 1) // block,
                    'invalid code extent or code-slot count')
            require(hashes >= special * hash_size and hashes + slots * hash_size <= len(cd),
                    'CodeDirectory hash table outside blob')
            require(ident < len(cd) and b'\0' in cd[ident:], 'invalid CodeDirectory identifier')
            stream.seek(0)
            for page in range(slots):
                data = stream.read(min(block, limit - page * block))
                require(hashlib.sha256(data).digest() == cd[hashes + page * 32:hashes + (page + 1) * 32],
                        f'{path.name}: original signing block {page} differs')
            cdhash = hashlib.sha256(cd).digest()[:20]
            require((cdhash, hash_type) in trust, f'{path.name}: cdhash absent from original trust module')
            result.append(dict(slot=slot, cdhash=cdhash.hex(), code_blocks_verified=slots,
                               signing_block_bytes=block, original_trust_entry_found=True))
        require(result, 'no supported CodeDirectory')
        return result


def audit_macho(path, trust, expected_kind):
    raw = path.read_bytes()
    require(len(raw) >= 32, 'truncated Mach-O')
    magic, cpu, subtype, kind, count, command_bytes = struct.unpack_from('<6I', raw)
    require((magic, cpu, subtype) == (0xfeedfacf, 0x100000c, 0), 'requires ordinary ARM64')
    require(kind == expected_kind, 'unexpected Mach-O file type')
    at, signature, dependencies = 32, None, []
    require(32 + command_bytes <= len(raw), 'load commands outside file')
    for _ in range(count):
        require(at + 8 <= 32 + command_bytes, 'truncated load command')
        cmd, size = struct.unpack_from('<II', raw, at)
        require(size >= 8 and at + size <= 32 + command_bytes, 'invalid load command')
        if cmd == 0x19:
            require(size >= 72, 'truncated segment command')
            va, vmsize, fileoff, filesize = struct.unpack_from('<4Q', raw, at + 24)
            require(va % 4096 == vmsize % 4096 == fileoff % 4096 == 0,
                    'segment is not directly 4K aligned')
            require(filesize <= vmsize and fileoff + filesize <= len(raw), 'invalid segment extent')
        elif cmd == 0x1d:
            require(size >= 16, 'truncated signature command')
            require(signature is None, 'duplicate signature command')
            signature = struct.unpack_from('<2I', raw, at + 8)
        elif cmd in (0xc, 0x80000018, 0x8000001f, 0xe):
            require(size >= 12, 'truncated dependency command')
            name_at, = struct.unpack_from('<I', raw, at + 8)
            require(12 <= name_at < size, 'invalid dependency string offset')
            dependencies.append(raw[at + name_at:at + size].split(b'\0', 1)[0].decode())
        at += size
    require(at == 32 + command_bytes and signature, 'invalid commands or missing signature')
    return dict(path=str(path.relative_to(REPO)), bytes=len(raw), arm64_subtype=0,
                filetype=kind, segments_4k_aligned=True, dependencies=dependencies,
                code_directories=code_directories(path, *signature, trust))


def audit(source, offsets, cache_manifest=None):
    decoded = source / 'decoded-complete'
    static = trust_entries(decoded / '044-17597-018.dmg.trustcache.bin')
    system = trust_entries(decoded / '044-18090-018.dmg.trustcache.bin')
    result = dict(apple_certificate_chain_verified=False, kernel_abi_verified=False,
                  apple_userspace_executed=False, ipados_boot_demonstrated=False,
                  source_images_modified=False, special_slot_blobs_verified=False,
                  trust_module_apple_chain_verified=False, whole_files_compared_to_ipsw=False,
                  files=[])
    for name, kind in (('sbin/launchd', 2), ('usr/lib/dyld', 7)):
        result['files'].append(audit_macho(source / 'os-minimal' / name, static, kind))
    mapping = json.loads((cache_manifest or source / 'runtime-cache-manifest.json').read_text())
    cache = {}
    paths = set()
    for entry in mapping['files']:
        path = (REPO / entry['path']).resolve()
        require(entry['name'] not in cache and path not in paths, 'duplicate runtime cache input')
        require(path.name == entry['name'], 'cache filename differs from manifest')
        paths.add(path)
        require(path.stat().st_size == entry['expected_bytes'], 'cache file size differs')
        with path.open('rb') as stream:
            header = stream.read(512)
            require(header[:16].rstrip(b'\0') == b'dyld_v1   arm64', 'unexpected cache architecture')
            sigoff, sigsize = struct.unpack_from('<2Q', header, offsets['codeSignatureOffset'])
            mapoff, mapcount = struct.unpack_from('<2I', header, 16)
            require(mapoff + mapcount * 32 <= path.stat().st_size, 'cache mapping table outside file')
            stream.seek(mapoff)
            for _ in range(mapcount):
                va, length, fileoff, _, _ = struct.unpack('<3Q2I', stream.read(32))
                require(va % 4096 == length % 4096 == fileoff % 4096 == 0,
                        'cache mapping is not 4K aligned')
                require(fileoff + length <= sigoff, 'cache mapping exceeds signed file data')
        uuid = header[offsets['uuid']:offsets['uuid'] + 16]
        cache[entry['name']] = (path, header, uuid)
        result['files'].append(dict(path=str(path.relative_to(REPO)), bytes=path.stat().st_size,
            uuid=uuid.hex(), mappings_4k_aligned=True,
            code_directories=code_directories(path, sigoff, sigsize, system)))
    main = cache['dyld_shared_cache_arm64']
    suboff, count = struct.unpack_from('<2I', main[1], offsets['subCacheArrayOffset'])
    require(count + 1 == len(cache), 'subcache count differs from runtime inputs')
    with main[0].open('rb') as stream:
        stream.seek(suboff)
        references = set()
        for _ in range(count):
            raw = stream.read(offsets['subcache_entry_bytes'])
            require(len(raw) == 56, 'unsupported subcache entry format')
            suffix = raw[24:56].split(b'\0', 1)[0].decode('ascii')
            key = 'dyld_shared_cache_arm64' + suffix
            require(key not in references, 'duplicate subcache reference')
            references.add(key)
            require(key in cache and cache[key][2] == raw[:16], 'subcache filename/UUID mismatch: ' + key)
        require(references == set(cache) - {'dyld_shared_cache_arm64'}, 'subcache input set mismatch')
    result.update(status='input_structure_and_code_hashes_passed', runtime_cache_files=len(cache),
                  runtime_cache_bytes=sum(p.stat().st_size for p, _, _ in cache.values()),
                  subcache_filename_uuid_matches=True, code_hashes_and_original_trust_membership_verified=True,
                  format_reference='apple-oss-distributions/dyld@a571176e8e00c47e95b95e3156820ebec0cbd5e6')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--format-offsets', type=Path, required=True)
    parser.add_argument('--cache-manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'refusing to overwrite output')
    try:
        report = audit(args.source.resolve(), json.loads(args.format_offsets.read_text()), args.cache_manifest)
    except (ValueError, OSError, struct.error) as exc:
        report = dict(status='failed', error=str(exc), ipados_boot_demonstrated=False)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, indent=2))
    raise SystemExit(report['status'] == 'failed')
