#!/usr/bin/env python3
"""Fetch the 21H461 OS and SystemOS DMG members for the nabu upstream-port candidate.

Companion to fetch_21h461_members.py: same remote-range approach, never the whole
IPSW. The OS member is zip-stored (raw ranged download with resume); SystemOS is
deflated (streamed through zipfile, restarted per member on interruption). Both
artifacts must hash to the upstream board.toml [ipsw.sha256] pins.
"""
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_21h461_members import OUT, URL, RangeFile

TARGETS = {
    '044-76040-038.dmg': '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d',
    '044-76034-038.dmg': 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f',
}
CHUNK = 8 << 20
RETRIES = 8


def ranged_get(start, end):
    for attempt in range(RETRIES):
        try:
            request = urllib.request.Request(URL, headers={'Range': f'bytes={start}-{end}'})
            with urllib.request.urlopen(request, timeout=300) as response:
                if response.status != 206:
                    raise OSError(f'expected 206, got {response.status}')
                return response.read()
        except (OSError, urllib.error.URLError):
            if attempt == RETRIES - 1:
                raise
            time.sleep(min(60, 2 ** attempt))
    raise OSError('unreachable')


def sha256_of(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_stored(archive, entry, destination):
    """Raw ranged download of a zip-stored member, resuming from the partial file."""
    partial = destination.with_suffix('.partial')
    header = archive.open(entry).peek(0)  # not used; offsets below come from the zip entry
    data_offset = None
    # zipfile exposes the local header via open(); compute the data start from the
    # central directory instead: header offset plus its own variable-size header.
    with archive.open(entry) as probe:
        data_offset = probe._fileobj._file.position if hasattr(probe, '_fileobj') else None
    if data_offset is None:
        # Fallback: stream through zipfile (slower path, still correct).
        stream_member(archive, entry, destination)
        return
    have = partial.stat().st_size if partial.is_file() else 0
    digest = hashlib.sha256()
    if have:
        # Restart the digest from the already-downloaded prefix.
        with partial.open('rb') as prefix:
            for chunk in iter(lambda: prefix.read(1 << 20), b''):
                digest.update(chunk)
    while have < entry.compress_size:
        block = ranged_get(data_offset + have, min(data_offset + entry.compress_size, have + CHUNK) - 1 - data_offset + data_offset)
        block = ranged_get(data_offset + have, data_offset + min(entry.compress_size, have + CHUNK) - 1)
        partial.open('ab').write(block)
        digest.update(block)
        have += len(block)
        print(f'  {entry.filename}: {have}/{entry.compress_size} bytes', flush=True)
    destination.unlink(missing_ok=True)
    partial.rename(destination)
    if digest.hexdigest() != TARGETS[destination.name]:
        raise SystemExit(f'{destination.name} sha256 mismatch: {digest.hexdigest()}')


def stream_member(archive, entry, destination):
    digest = hashlib.sha256()
    partial = destination.with_suffix('.partial')
    partial.unlink(missing_ok=True)
    with archive.open(entry) as source, partial.open('wb') as target:
        while chunk := source.read(CHUNK):
            target.write(chunk)
            digest.update(chunk)
            print(f'  {entry.filename}: {target.tell()}/{entry.file_size} bytes', flush=True)
    if partial.stat().st_size != entry.file_size:
        partial.unlink()
        raise SystemExit(f'incomplete extraction of {entry.filename}')
    destination.unlink(missing_ok=True)
    partial.rename(destination)
    if digest.hexdigest() != TARGETS[destination.name]:
        raise SystemExit(f'{destination.name} sha256 mismatch: {digest.hexdigest()}')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    stream = RangeFile(URL)
    archive = zipfile.ZipFile(stream)
    records = []
    for name, pin in TARGETS.items():
        destination = OUT / name
        member = 'Firmware/' + name
        entry = archive.getinfo(member)
        if destination.is_file() and destination.stat().st_size == entry.file_size and sha256_of(destination) == pin:
            print(f'{name}: already present and pinned')
            records.append({'member': member, 'size': entry.file_size, 'sha256': pin, 'skipped': True})
            continue
        print(f'{name}: fetching ({entry.file_size} bytes, zip type {entry.compress_type})', flush=True)
        if entry.compress_type == 0:
            fetch_stored(archive, entry, destination)
        else:
            stream_member(archive, entry, destination)
        records.append({'member': member, 'size': entry.file_size, 'sha256': pin, 'skipped': False})
        (destination.with_suffix('.json')).write_text(json.dumps(records[-1], indent=2) + '\n')
        print(f'{name}: sha256 pinned OK', flush=True)
    print(json.dumps(records, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
