#!/usr/bin/env python3
"""Read-only local inspector for a user-provided iPadOS 17 IPSW or unpacked root.

No network, no device, no build, no QEMU. Reads only the root BuildManifest.plist
(and Restore.plist when present) via zipfile/plistlib; never extracts DMG,
kernelcache or system members, never runs extractall, never writes to the input.
The report goes to a new timestamped JSON next to this script unless --output is
given (which must be a new, non-existing path). No whole-package hash.
"""
import argparse
import hashlib
import io
import json
import plistlib
import struct
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
TZ = timezone(timedelta(hours=8))
PLIST_CAP = 8 << 20          # decompressed cap per plist, bytes
STREAM_CAP = 1 << 20         # per single read() ceiling while streaming
MANIFEST_NAMES = ('BuildManifest.plist', 'Restore.plist')
MANIFEST_NAMES_LOWER = frozenset(name.lower() for name in MANIFEST_NAMES)


class InspectError(Exception):
    """Raised for any rejected input or unsafe condition."""


def require(condition, message):
    if not condition:
        raise InspectError(message)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def stream_member(archive, member, cap):
    """Read one member with size and streaming caps; explicit failure only."""
    require(member.file_size <= cap,
            'member %r uncompressed size %d exceeds %d-byte cap'
            % (member.filename, member.file_size, cap))
    parts, total = [], 0
    with archive.open(member, 'r') as stream:
        while True:
            chunk = stream.read(min(STREAM_CAP, cap + 1 - total))
            if not chunk:
                break
            parts.append(chunk)
            total += len(chunk)
            require(total <= cap,
                    'member %r decompression exceeded %d-byte cap while streaming'
                    % (member.filename, cap))
    return b''.join(parts)


def allowed_manifest_names(members):
    """Pick root-level manifest members; case-insensitive duplicates are
    rejected as ambiguous (two members cannot map to one extracted file)."""
    chosen = {}
    for member in members:
        name = member.filename
        lowered = name.lower()
        if lowered in MANIFEST_NAMES_LOWER:
            require(lowered not in chosen,
                    'duplicate manifest member %r (case-insensitive match of %r)'
                    % (name, chosen[lowered].filename if lowered in chosen else lowered))
            chosen[lowered] = member
    return chosen


def load_manifests(archive, members):
    """Load each matched manifest under its canonical MANIFEST_NAMES spelling."""
    loaded = {}
    for lowered, member in allowed_manifest_names(members).items():
        canonical = next(candidate for candidate in MANIFEST_NAMES
                         if candidate.lower() == lowered)
        loaded[canonical] = stream_member(archive, member, PLIST_CAP)
    return loaded


def manifest_summary(data):
    fields = plistlib.loads(data)
    info = {
        'ProductVersion': fields.get('ProductVersion'),
        'ProductBuildVersion': fields.get('ProductBuildVersion'),
        'SupportedProductTypes': fields.get('SupportedProductTypes'),
        'build_identities': [],
    }
    for identity in fields.get('BuildIdentities', []):
        manifest = identity.get('Manifest') or {}
        info['build_identities'].append({
            'ApBoardId': identity.get('ApBoardId'),
            'ApChipID': identity.get('ApChipID'),
            'ApProductType': identity.get('ApProductType'),
            'Info': {key: identity.get('Info', {}).get(key) for key in
                     ('DeviceClass', 'BoardConfig', 'BuildNumber', 'FirmwareVersion',
                      'Variant', 'RestoreBehavior') if key in identity.get('Info', {})},
            'KernelCachePath': (manifest.get('KernelCache') or {}).get('Info', {}).get('Path'),
            'OSPath': (manifest.get('OS') or {}).get('Info', {}).get('Path'),
        })
    return info


def version_gate(summary, names):
    """Report the actual version; only main-version-17 with iPad support passes."""
    version = summary.get('ProductVersion') or ''
    types = [str(value) for value in (summary.get('SupportedProductTypes') or [])]
    major = version.split('.', 1)[0]
    is_17 = major == '17'
    has_ipad = any(value.startswith('iPad') for value in types)
    return {
        'is_ios17': is_17,
        'has_ipad_support': has_ipad,
        'accepted': is_17 and has_ipad,
        'actual_values': {'ProductVersion': version or None,
                          'ProductBuildVersion': summary.get('ProductBuildVersion'),
                          'SupportedProductTypes': types},
        'names': sorted(names),
        'policy': 'main version 17 and at least one iPad* product type required; '
                  'no specific build or device model is required or assumed',
    }


def inspect_archive(path):
    stat = path.stat()
    report = {'input': {'path': str(path), 'size_bytes': stat.st_size,
                        'mtime': datetime.fromtimestamp(stat.st_mtime, TZ).isoformat()}}
    with zipfile.ZipFile(path, 'r') as archive:
        members = archive.infolist()
        require(len(members) <= 4096, 'archive has %d members; unexpected' % len(members))
        loaded = load_manifests(archive, members)
        report['members_total'] = len(members)
        report['plist_members'] = {
            name: {'bytes': len(data), 'sha256': sha256_hex(data)}
            for name, data in loaded.items()}
        build = loaded.get('BuildManifest.plist')
        require(build is not None, 'BuildManifest.plist not found at archive root')
        report['build_manifest'] = manifest_summary(build)
        report['notable_members'] = []
        for member in members:
            lowered = member.filename.lower()
            if (lowered.endswith('.dmg') or 'dyld' in lowered
                    or lowered.startswith('kernelcache')
                    or lowered in [name.lower() for name in MANIFEST_NAMES]):
                report['notable_members'].append({
                    'name': member.filename, 'compression': member.compress_type,
                    'compressed_bytes': member.compress_size,
                    'uncompressed_bytes': member.file_size})
    return report


def inspect_directory(path):
    report = {'input': {'path': str(path), 'mode': 'directory'}}
    members = []
    for name in MANIFEST_NAMES:
        file = path / name
        if file.is_file():
            stat = file.stat()
            data = file.read_bytes()
            require(len(data) <= PLIST_CAP,
                    '%s exceeds %d-byte cap' % (name, PLIST_CAP))
            members.append(name)
            report.setdefault('plist_members', {})[name] = {
                'bytes': len(data), 'sha256': sha256_hex(data)}
    require('BuildManifest.plist' in members, 'root BuildManifest.plist not found')
    report['build_manifest'] = manifest_summary(
        (path / 'BuildManifest.plist').read_bytes())
    report['members_total'] = len(members)
    report['notable_members'] = [
        {'name': entry.name, 'bytes': entry.stat().st_size}
        for entry in path.iterdir()
        if entry.is_file() and (entry.name.lower().endswith('.dmg')
                                or 'dyld' in entry.name.lower()
                                or entry.name.lower().startswith('kernelcache'))]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only iPadOS 17 IPSW inspector.')
    parser.add_argument('input', type=Path, help='local .ipsw file or unpacked root directory')
    parser.add_argument('--output', type=Path, default=None,
                        help='report path (must not exist); default: timestamped file here')
    args = parser.parse_args(argv)
    path = args.input
    require(path.exists(), 'input does not exist: %s' % path)
    require(path.is_file() or path.is_dir(), 'input is neither file nor directory: %s' % path)
    if args.output is not None:
        require(not args.output.exists(), 'refusing to overwrite existing output: %s' % args.output)
        require(path.resolve() != args.output.resolve(),
                'refusing to overwrite the input with the report')
    try:
        report = inspect_directory(path) if path.is_dir() else inspect_archive(path)
    except InspectError as exc:
        print(json.dumps({'error': str(exc), 'accepted': False}, ensure_ascii=False))
        return 2
    gate = version_gate(report['build_manifest'], report['plist_members'])
    report['version_gate'] = gate
    report['status'] = {
        'kernelcache_extracted': False, 'launchd_input_ready': False,
        'compatibility_verified': False,
        'note': 'metadata only: KernelCache and a real launchd input are not '
                'extracted or executed here; compatibility with the current '
                'XNU tree is unverified; nothing is bootable by this report',
    }
    report['generated_at'] = datetime.now(TZ).isoformat()
    payload = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    output = args.output or (HERE / ('ipsw-inspect-%s.json'
                                     % datetime.now(TZ).strftime('%Y%m%d-%H%M%S')))
    output.write_text(payload, encoding='utf-8')
    print(json.dumps({'output': str(output), 'accepted': gate['accepted'],
                      'actual_values': gate['actual_values']}, ensure_ascii=False))
    return 0 if gate['accepted'] else 1


if __name__ == '__main__':
    sys.exit(main())
