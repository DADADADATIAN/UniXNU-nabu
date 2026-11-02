#!/usr/bin/env python3
"""Fetch the small 21H461 (iPad7,1) IPSW members for the nabu upstream-port candidate.

Mirrors the upstream UniXNU ipsw.py behaviour: the remote IPSW is never downloaded
as a whole. The zip central directory and only the needed members are read with
HTTP range requests. Members land in system-17.7.11-21H461-20261024/ next to this
tool, each with a sidecar record (component, member path, size, sha256, source).

The kernelcache pin of the upstream board is the sha256 of the LZFSE-decompressed
arm64 cache, which needs macOS compression_tool; that check stays on CI. Here we
pin the member-level sha256 (the same level board.toml [ipsw.sha256] uses for the
OS/SystemOS DMGs) and verify the trust caches against the two upstream payload
pins when they match.
"""
import hashlib
import io
import json
import plistlib
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

URL = ('https://updates.cdn-apple.com/2025SpringFCS/fullrestores/122-77166/'
       'DCA6CFE8-90E9-4B92-880D-3DE171798E40/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw')
OUT = Path(__file__).resolve().parent / 'system-17.7.11-21H461-20261024'
BOARD = {'product': 'iPad7,1', 'version': '17.7.11', 'build': '21H461',
         'device_class': 'j120ap', 'chip_id': 0x8011, 'board_id': 12}
COMPONENTS = ['KernelCache', 'DeviceTree', 'StaticTrustCache', 'Cryptex1,SystemTrustCache']
# Upstream UniXNU-sheng board.toml: [payload] trust_cache_sha256 (static, system).
TRUST_PINS = {'7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7': 'static',
              '8900d6a93d7a59ce1a872a5c081e559f4240a218f97e12d44d22dda46644d68f': 'system'}
# Upstream [ipsw.sha256] pins of the two payload-stage DMGs (recorded, not fetched).
DMG_PINS = {'044-76040-038.dmg': '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d',
            '044-76034-038.dmg': 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f'}
CHUNK = 8 << 20


class RangeFile(io.RawIOBase):
    """Seekable remote-file view over HTTP range requests (adapted from upstream ipsw.py)."""

    def __init__(self, url, block=CHUNK, retries=5):
        self.url, self.block, self.retries = url, block, retries
        self.position = 0
        self.cache = {}
        with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=60) as response:
            self.size = int(response.headers['Content-Length'])
        with urllib.request.urlopen(urllib.request.Request(url, headers={'Range': 'bytes=0-0'}), timeout=60) as response:
            if response.status != 206:
                raise SystemExit(f'{url} does not support range requests')

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        self.position = {0: offset, 1: self.position + offset, 2: self.size + offset}[whence]
        return self.position

    def _block(self, index):
        if index not in self.cache:
            if len(self.cache) >= 4:
                self.cache.pop(next(iter(self.cache)))
            start = index * self.block
            end = min(start + self.block, self.size) - 1
            for attempt in range(self.retries):
                try:
                    request = urllib.request.Request(self.url, headers={'Range': f'bytes={start}-{end}'})
                    with urllib.request.urlopen(request, timeout=180) as response:
                        data = response.read()
                    if len(data) != end - start + 1:
                        raise OSError('short range response')
                    self.cache[index] = data
                    break
                except (OSError, urllib.error.URLError):
                    if attempt == self.retries - 1:
                        raise
                    time.sleep(2 ** attempt)
        return self.cache[index]

    def readinto(self, buffer):
        want = min(len(buffer), self.size - self.position)
        done = 0
        while done < want:
            index, inside = divmod(self.position, self.block)
            data = self._block(index)[inside:inside + want - done]
            buffer[done:done + len(data)] = data
            done += len(data)
            self.position += len(data)
        return done


def im4p_parts(data):
    """Top-level DER items of an IM4P container (the members are DER-wrapped)."""
    def der(at):
        tag, length = data[at], data[at + 1]
        at += 2
        if length & 0x80:
            count = length & 0x7f
            length = int.from_bytes(data[at:at + count], 'big')
            at += count
        return tag, at, length
    _, start, length = der(0)
    items, at = [], start
    while at < start + length:
        _, body, size = der(at)
        items.append(data[body:body + size])
        at = body + size
    if len(items) < 4 or items[0] != b'IM4P':
        raise SystemExit('member is not an IM4P')
    return items[1].decode(), items[2].decode(errors='replace'), items[3]


def main():
    stream = RangeFile(URL)
    print(f'ipsw: {URL.rsplit("/", 1)[-1]} size {stream.size} bytes')
    archive = zipfile.ZipFile(stream)
    manifest = plistlib.loads(archive.read('BuildManifest.plist'))
    if (manifest['ProductVersion'], manifest['ProductBuildVersion']) != (BOARD['version'], BOARD['build']):
        raise SystemExit(f"unexpected version {manifest['ProductVersion']} {manifest['ProductBuildVersion']}")
    identity = None
    for item in manifest['BuildIdentities']:
        info = item['Info']
        if (info['DeviceClass'] == BOARD['device_class'] and info['RestoreBehavior'] == 'Erase'
                and int(item['ApChipID'], 16) == BOARD['chip_id'] and int(item['ApBoardID'], 16) == BOARD['board_id']):
            identity = item
            break
    if identity is None:
        raise SystemExit(f"no Erase identity for {BOARD['device_class']}")
    print(f"identity: {BOARD['device_class']} chip {item['ApChipID']} board {item['ApBoardID']}")
    OUT.mkdir(parents=True, exist_ok=True)
    records = []
    for component in COMPONENTS:
        try:
            name = identity['Manifest'][component]['Info']['Path']
        except KeyError:
            raise SystemExit(f'component {component} missing from manifest')
        entry = archive.getinfo(name)
        digest = hashlib.sha256()
        destination = OUT / entry.filename.rsplit('/', 1)[-1]
        partial = destination.with_suffix(destination.suffix + '.partial')
        print(f'extract {component}: {name} ({entry.file_size} bytes)')
        with archive.open(name) as source, partial.open('wb') as target:
            while chunk := source.read(CHUNK):
                target.write(chunk)
                digest.update(chunk)
        if partial.stat().st_size != entry.file_size:
            partial.unlink()
            raise SystemExit(f'incomplete extraction of {name}')
        destination.unlink(missing_ok=True)
        partial.rename(destination)
        record = {'component': component, 'member': name, 'size': entry.file_size,
                  'sha256': digest.hexdigest(), 'source': URL, 'build': BOARD['build'],
                  'device_class': BOARD['device_class']}
        raw = destination.read_bytes()
        if raw[:1] == b'\x30':
            kind, version, payload = im4p_parts(raw)
            payload_digest = hashlib.sha256(payload).hexdigest()
            record['im4p'] = {'type': kind, 'version': version, 'payload_size': len(payload),
                              'payload_sha256': payload_digest, 'payload_magic': payload[:4].hex()}
            if not destination.with_suffix('.payload').is_file():
                destination.with_suffix('.payload').write_bytes(payload)
        if digest.hexdigest() in TRUST_PINS:
            record['matches_upstream_payload_pin'] = TRUST_PINS[digest.hexdigest()]
        records.append(record)
        (destination.with_suffix('.json')).write_text(json.dumps(record, indent=2) + '\n')

    # Reproduce the upstream original static+system trust bundle (common
    # scripts/build-original-system-trust.py) from the two fetched modules and
    # check it against the first upstream [payload] trust pin.
    static = (OUT / '044-76040-038.dmg.trustcache').with_suffix('.payload').read_bytes()
    system = (OUT / '044-76034-038.dmg.trustcache').with_suffix('.payload').read_bytes()
    for name, module in (('static', static), ('system', system)):
        if struct.unpack_from('<I', module)[0] != 2 or len(module) != 24 + struct.unpack_from('<I', module, 20)[0] * 24:
            raise SystemExit(f'{name} trust module is not a complete version-2 module')
    bundle = struct.pack('<3I', 2, 12, 12 + len(static)) + static + system
    bundle_digest = hashlib.sha256(bundle).hexdigest()
    (OUT / 'original-static-system.bundle').write_bytes(bundle)
    bundle_record = {
        'file': 'original-static-system.bundle', 'size': len(bundle), 'sha256': bundle_digest,
        'construction': 'header(2,12,12+len(static)) + static + system payloads of the two fetched IM4P members',
        'matches_upstream_payload_pin': TRUST_PINS.get(bundle_digest),
        'expected': '7416ca4f... (upstream board.toml [payload] trust_cache_sha256[0])'}

    dmgs = []
    for entry in archive.infolist():
        if entry.filename.rsplit('/', 1)[-1] in DMG_PINS:
            dmgs.append({'member': entry.filename, 'size': entry.file_size,
                         'upstream_sha256_pin': DMG_PINS[entry.filename.rsplit('/', 1)[-1]],
                         'fetched': False})
    summary = {'url': URL, 'ipsw_size': stream.size, 'board': BOARD,
               'fetched': records, 'trust_bundle': bundle_record, 'deferred_dmgs': dmgs,
               'note': 'kernelcache decompressed-pin check (f18b4df8...) needs macOS compression_tool; run on CI'}
    (OUT / 'fetch-manifest.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'{len(records)} members -> {OUT}')
    for record in records:
        pin = record.get('matches_upstream_payload_pin')
        extra = f' [upstream {pin} trust pin]' if pin else ''
        print(f"  {record['component']}: {record['sha256'][:16]}...{extra}")
    print(f"  trust bundle: {bundle_digest[:16]}... matches pin: {bundle_record['matches_upstream_payload_pin']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
