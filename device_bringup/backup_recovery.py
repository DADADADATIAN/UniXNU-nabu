"""Copy nabu recovery material to the PC; all tablet block access is read-only.

Ubuntu, userdata, super and cust are deliberately excluded. No restore commands
are generated or executed. Existing historical backups are never overwritten.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import threading
import time
import uuid
import zlib


# Your tablet's ADB serial (`adb devices -l`). The project never ships a
# serial; every device command runs against this user-supplied value only.
SERIAL = os.environ.get('NABU_ADB_SERIAL', '')
EXPECTED_DISKS = {
    'sda': 125585850368,
    'sdb': 8388608,
    'sdc': 8388608,
    'sdd': 33554432,
    'sde': 2147483648,
    'sdf': 167772160,
}
SDA_NAMES = (
    'ssd', 'keystore', 'frp', 'countrycode', 'misc', 'devinfo',
    'oem_misc1', 'vbmeta_system_a', 'vbmeta_system_b', 'esp',
)
EXCLUDED = ('linux', 'userdata', 'super', 'cust', 'metadata',
            'logfs', 'oops', 'logdump', 'minidump', 'rawdump')


def remote(command):
    if not SERIAL:
        raise RuntimeError('Set NABU_ADB_SERIAL to your tablet ADB serial first')
    result = subprocess.run(
        ['adb', '-s', SERIAL, 'exec-out', 'su', '-c', command],
        capture_output=True, timeout=40,
    )
    if result.returncode:
        raise RuntimeError(f'{command}: {result.stderr.decode(errors="replace")}')
    return result.stdout


def text_command(command):
    return remote(command).decode().strip()


def read_blocks(disk, start, count):
    if disk not in EXPECTED_DISKS or start < 0 or not 0 < count <= 4096:
        raise ValueError('Read outside metadata limits')
    if (start + count) * 4096 > EXPECTED_DISKS[disk]:
        raise ValueError('Read exceeds disk')
    data = remote(
        f'dd if=/dev/block/{disk} bs=4096 skip={start} count={count} 2>/dev/null'
    )
    if len(data) != count * 4096:
        raise RuntimeError(f'Short metadata read: {disk}, {len(data)} bytes')
    return data


def header(data, expected_lba):
    if data[:8] != b'EFI PART':
        raise ValueError('Missing GPT signature')
    length = struct.unpack_from('<I', data, 12)[0]
    if not 92 <= length <= 4096:
        raise ValueError('Invalid GPT header size')
    actual_crc = struct.unpack_from('<I', data, 16)[0]
    crc_data = bytearray(data[:length])
    crc_data[16:20] = bytes(4)
    if zlib.crc32(crc_data) != actual_crc:
        raise ValueError('GPT header CRC mismatch')
    current, alternate, first, last = struct.unpack_from('<4Q', data, 24)
    if current != expected_lba:
        raise ValueError('Unexpected GPT header location')
    entries_lba, count, entry_size, entries_crc = struct.unpack_from('<QIII', data, 72)
    if entry_size < 128 or entry_size % 128 or not 0 < count * entry_size <= 1024**2:
        raise ValueError('Unexpected GPT entry geometry')
    return {
        'current_lba': current, 'alternate_lba': alternate,
        'first_usable_lba': first, 'last_usable_lba': last,
        'disk_guid': str(uuid.UUID(bytes_le=data[56:72])),
        'entries_lba': entries_lba, 'entry_count': count,
        'entry_size': entry_size, 'entries_crc32': entries_crc,
    }


def inspect_gpt(disk):
    final_lba = EXPECTED_DISKS[disk] // 4096 - 1
    p = header(read_blocks(disk, 1, 1), 1)
    b = header(read_blocks(disk, final_lba, 1), final_lba)
    if p['alternate_lba'] != final_lba or b['alternate_lba'] != 1:
        raise ValueError(f'{disk}: GPT alternate location mismatch')
    for field in ('disk_guid', 'first_usable_lba', 'last_usable_lba',
                  'entry_count', 'entry_size', 'entries_crc32'):
        if p[field] != b[field]:
            raise ValueError(f'{disk}: GPT copies disagree: {field}')
    length = p['entry_count'] * p['entry_size']
    blocks = (length + 4095) // 4096
    a = read_blocks(disk, p['entries_lba'], blocks)[:length]
    c = read_blocks(disk, b['entries_lba'], blocks)[:length]
    if a != c or zlib.crc32(a) != p['entries_crc32']:
        raise ValueError(f'{disk}: GPT entry CRC or mirror mismatch')
    if p['entries_lba'] < 2 or p['entries_lba'] + blocks > p['first_usable_lba']:
        raise ValueError(f'{disk}: GPT primary entries overlap usable area')
    if b['entries_lba'] <= p['last_usable_lba'] or b['entries_lba'] + blocks > final_lba:
        raise ValueError(f'{disk}: GPT backup entries overlap usable area')
    partitions = []
    for index in range(p['entry_count']):
        row = a[index*p['entry_size']:(index+1)*p['entry_size']]
        if row[:16] == bytes(16):
            continue
        first, last = struct.unpack_from('<QQ', row, 32)
        if not p['first_usable_lba'] <= first <= last <= p['last_usable_lba']:
            raise ValueError(f'{disk}: Invalid partition range')
        partitions.append({
            'number': index + 1,
            'name': row[56:128].decode('utf-16-le').rstrip('\0'),
            'device': f'/dev/block/{disk}{index+1}',
            'first_lba': first, 'last_lba': last,
            'bytes': (last-first+1)*4096,
            'type_guid': str(uuid.UUID(bytes_le=row[:16])),
            'partition_guid': str(uuid.UUID(bytes_le=row[16:32])),
        })
    return {
        'bytes': EXPECTED_DISKS[disk], 'sector_bytes': 4096,
        'primary_header': p, 'backup_header': b,
        'primary_header_crc_valid': True, 'backup_header_crc_valid': True,
        'entry_arrays_crc_valid_and_identical': True,
        'partitions': partitions,
    }


def copy_device(device, expected, target):
    allowed = {f'/dev/block/{x}' for x in EXPECTED_DISKS if x != 'sda'}
    allowed.update(f'/dev/block/by-name/{x}' for x in SDA_NAMES)
    if device not in allowed or target.exists():
        raise ValueError('Unexpected source or existing destination')
    partial = target.with_suffix(target.suffix + '.partial')
    if partial.exists():
        raise ValueError('Previous partial backup exists')
    proc = subprocess.Popen(
        ['adb', '-s', SERIAL, 'exec-out', 'su', '-c',
         f'dd if={device} bs=1048576 2>/dev/null'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    watchdog = threading.Timer(1800, proc.kill)
    watchdog.start()
    total = 0
    last = time.monotonic()
    try:
        with partial.open('xb') as output:
            while chunk := proc.stdout.read(1024**2):
                total += len(chunk)
                if total > expected:
                    raise RuntimeError('Read exceeded expected source size')
                output.write(chunk)
                now = time.monotonic()
                if now-last >= 5:
                    print(f'{target.name}: {total/1024**2:.1f}/{expected/1024**2:.1f} MiB', flush=True)
                    last = now
        error = proc.stderr.read().decode(errors='replace')
        code = proc.wait(timeout=30)
        if code != 0 or total != expected or partial.stat().st_size != expected:
            raise RuntimeError(f'Incomplete backup {target.name}: {total}/{expected}; exit {code}; {error}')
        partial.rename(target)
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    print(f'COMPLETE {target.name}: {total} bytes', flush=True)
    return {'file': target.name, 'source': device, 'bytes': total,
            'exact_size_verified': True, 'adb_dd_exit_code': code}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists():
        raise SystemExit('Use a new output directory; old backups are preserved')
    if text_command('getprop ro.product.device') != 'nabu':
        raise SystemExit('Unexpected product')
    if not text_command('id').startswith('uid=0(root)'):
        raise SystemExit('Root read access unavailable')
    identity = {name: text_command(f'getprop {name}') for name in (
        'ro.product.device', 'ro.product.model', 'ro.serialno',
        'ro.build.fingerprint', 'ro.boot.slot_suffix', 'ro.boot.flash.locked',
    )}
    if identity['ro.serialno'] != SERIAL:
        raise SystemExit('Device identity mismatch')
    gpts = {}
    for disk, size in EXPECTED_DISKS.items():
        live_size = int(text_command(f'blockdev --getsize64 /dev/block/{disk}'))
        live_sector = int(text_command(f'blockdev --getss /dev/block/{disk}'))
        if live_size != size or live_sector != 4096:
            raise SystemExit(f'Unexpected disk geometry: {disk}')
        gpts[disk] = inspect_gpt(disk)
        print(f'GPT VERIFIED {disk}: both headers and entry arrays', flush=True)
    sda_parts = {p['name']: p for p in gpts['sda']['partitions']}
    if sda_parts.get('linux', {}).get('bytes') != 64000000000:
        raise SystemExit('Ubuntu geometry changed; inspect before continuing')
    if sda_parts.get('userdata', {}).get('bytes') != 50363834368:
        raise SystemExit('Android data geometry changed; inspect before continuing')
    if sda_parts.get('esp', {}).get('bytes') != 350105600:
        raise SystemExit('ESP geometry changed')
    for name in SDA_NAMES:
        part = sda_parts[name]
        if text_command(f'readlink -f /dev/block/by-name/{name}') != part['device']:
            raise SystemExit(f'Partition alias mismatch: {name}')
    plan = [(f'/dev/block/{disk}', size, f'{disk}-firmware-lun.img')
            for disk, size in EXPECTED_DISKS.items() if disk != 'sda']
    plan += [(f'/dev/block/by-name/{name}', sda_parts[name]['bytes'], f'{name}.img')
             for name in SDA_NAMES]
    expected_total = sum(x[1] for x in plan)
    if shutil.disk_usage(out.parent).free < expected_total + 1024**3:
        raise SystemExit('Insufficient PC space')
    mounts = text_command('cat /proc/mounts')
    out.mkdir()
    report = {
        'status': 'in_progress', 'serial': SERIAL, 'identity': identity,
        'started_at': datetime.now(timezone(timedelta(hours=8))).isoformat(),
        'purpose': 'Recovery of partition layout, boot firmware and device-specific material',
        'authorization': 'User requested only anti-brick recovery backups; Ubuntu backup excluded',
        'raw_block_writes': False, 'mount_changes': False, 'files_pushed_to_tablet': False,
        'reboot_or_flash_commands': False, 'excluded_partition_contents': EXCLUDED,
        'scope_note': 'Small firmware LUNs are copied whole, including their GPT and padding. sda is never copied whole.',
        'hash_verification': 'Not performed, following historical preference; exact byte sizes and GPT CRCs checked',
        'consistency_note': 'Read-only collection from running Android; filesystems are not frozen. This is not an Android user-data snapshot.',
        'gpt': gpts, 'files': [], 'planned_image_bytes': expected_total,
    }

    def save():
        (out/'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

    save()
    (out/'mounts-before.txt').write_text(mounts+'\n', encoding='utf-8')
    try:
        for disk, info in gpts.items():
            p, b = info['primary_header'], info['backup_header']
            blocks = (p['entry_count']*p['entry_size']+4095)//4096
            ranges = [('primary', 0, p['entries_lba']+blocks),
                      ('backup', b['entries_lba'], info['bytes']//4096-b['entries_lba'])]
            for label, start, count in ranges:
                name = f'{disk}-gpt-{label}.bin'
                data = read_blocks(disk, start, count)
                (out/name).write_bytes(data)
                report['files'].append({'file': name, 'source': f'/dev/block/{disk}',
                                        'offset_bytes': start*4096, 'bytes': len(data),
                                        'exact_size_verified': True})
        save()
        print(f'BACKUP PLAN: {expected_total} bytes ({expected_total/1024**3:.3f} GiB); no Ubuntu or userdata', flush=True)
        for source, size, filename in plan:
            report['files'].append(copy_device(source, size, out/filename))
            save()
        for disk in EXPECTED_DISKS:
            if inspect_gpt(disk) != gpts[disk]:
                raise RuntimeError(f'GPT changed during collection: {disk}')
        for item in report['files']:
            if (out/item['file']).stat().st_size != item['bytes']:
                raise RuntimeError('Local backup length changed')
        report['gpt_unchanged_after_collection'] = True
        report['total_backup_bytes'] = sum(x['bytes'] for x in report['files'])
        report['status'] = 'complete'
        report['finished_at'] = datetime.now(timezone(timedelta(hours=8))).isoformat()
        save()
        print(f'RECOVERY BACKUP COMPLETE: {out}', flush=True)
    except BaseException as exc:
        report['status'] = 'failed'
        report['error'] = str(exc)
        save()
        raise


if __name__ == '__main__':
    main()
