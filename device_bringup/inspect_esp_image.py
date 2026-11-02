"""Inspect the local FAT32 ESP backup and save current text configurations."""
import json
from pathlib import Path
import struct

OUT = Path(__file__).resolve().parent / 'evidence'
image = OUT / 'nabu-esp-before-stage1-20261021.img'
files = []
with image.open('rb') as f:
    boot = f.read(4096)
    bps = struct.unpack_from('<H', boot, 11)[0]
    spc = boot[13]
    reserved = struct.unpack_from('<H', boot, 14)[0]
    fats = boot[16]
    fat_sectors = struct.unpack_from('<I', boot, 36)[0]
    root_cluster = struct.unpack_from('<I', boot, 44)[0]
    if boot[82:87] != b'FAT32' or bps not in (512, 1024, 2048, 4096):
        raise SystemExit('Unexpected filesystem')
    f.seek(reserved * bps)
    fat = f.read(fat_sectors * bps)
    base = (reserved + fats * fat_sectors) * bps
    cluster_bytes = bps * spc

    def chain(first, limit=1024 * 1024):
        data = bytearray()
        seen = set()
        current = first
        while 2 <= current < 0x0ffffff8:
            if current in seen or len(data) + cluster_bytes > limit:
                raise RuntimeError('Invalid or excessive FAT chain')
            seen.add(current)
            f.seek(base + (current - 2) * cluster_bytes)
            data += f.read(cluster_bytes)
            current = struct.unpack_from('<I', fat, current * 4)[0] & 0x0fffffff
        return bytes(data)

    def directory(cluster, parent='', depth=0):
        raw = chain(cluster)
        long = []
        for pos in range(0, len(raw), 32):
            item = raw[pos:pos + 32]
            if item[0] == 0:
                break
            if item[0] == 0xe5:
                long = []
                continue
            attr = item[11]
            if attr == 15:
                long.append((item[0] & 31, item[1:11] + item[14:26] + item[28:32]))
                continue
            base_name = item[:8].decode('ascii', errors='replace').rstrip()
            extension = item[8:11].decode('ascii', errors='replace').rstrip()
            name = base_name + ('.' + extension if extension else '')
            if long:
                name = b''.join(x for _, x in sorted(long)).decode('utf-16-le').split('\0')[0].rstrip('\uffff')
            long = []
            if name in ('.', '..') or attr & 8:
                continue
            first = (struct.unpack_from('<H', item, 20)[0] << 16) | struct.unpack_from('<H', item, 26)[0]
            size = struct.unpack_from('<I', item, 28)[0]
            path = parent + '/' + name
            files.append({'path': path, 'directory': bool(attr & 16), 'bytes': size})
            if attr & 16:
                if depth < 10:
                    directory(first, path, depth + 1)
            elif 0 < size < 1024 * 1024 and (name.lower().endswith(('.conf', '.txt', '.toml', '.json')) or
                                            name.lower() == 'goprotate_aa64.efi'):
                target = OUT / 'esp-before' / path.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(chain(first)[:size])
    directory(root_cluster)
(OUT / 'esp-before-files.json').write_text(json.dumps(files, indent=2) + '\n')
for item in files:
    if item['path'].startswith(('/EFI/UniXNU', '/EFI/Boot/refind', '/EFI/ubuntu', '/EFI/android')):
        print(item)
config = OUT / 'esp-before/EFI/Boot/refind.conf'
print(config.read_text(encoding='utf-8-sig')[-1300:])
