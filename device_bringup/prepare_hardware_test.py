"""Prepare a nabu hardware test using read-only ADB and local files only.

No tablet mounts, pushes, partition writes, installation or reboot. Requires the
documented post-Ubuntu-removal layout; preserves all previous evidence.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import zipfile

import backup_recovery as backup


ROOT = Path(__file__).resolve().parent
BUNDLE = ROOT / 'xnu_stage'
REMOVAL = ROOT / 'evidence/nabu-ubuntu-removal-20261022'
RECOVERY = ROOT / 'evidence/nabu-recovery-20261022'
TZ = timezone(timedelta(hours=8))


class FatImage:
    """Read the local FAT32 snapshot without mounting it."""

    def __init__(self, path):
        self.data = path.read_bytes()
        boot = self.data[:4096]
        self.bps = struct.unpack_from('<H', boot, 11)[0]
        self.spc = boot[13]
        reserved = struct.unpack_from('<H', boot, 14)[0]
        fats = boot[16]
        sectors = struct.unpack_from('<I', boot, 32)[0]
        fat_sectors = struct.unpack_from('<I', boot, 36)[0]
        root = struct.unpack_from('<I', boot, 44)[0]
        if (boot[82:87] != b'FAT32' or boot[510:512] != b'\x55\xaa'
                or self.bps not in (512, 1024, 2048, 4096)
                or not self.spc or self.spc & (self.spc-1)
                or fats != 2 or sectors*self.bps != len(self.data)):
            raise ValueError('Unexpected FAT32 snapshot geometry')
        fat_start = reserved*self.bps
        fat_bytes = fat_sectors*self.bps
        flags = struct.unpack_from('<H', boot, 40)[0]
        active = (flags & 15) if flags & 0x80 else 0
        if active >= fats:
            raise ValueError('Invalid active FAT index')
        self.fat = self.data[fat_start+active*fat_bytes:fat_start+(active+1)*fat_bytes]
        if not flags & 0x80 and self.fat != self.data[fat_start+fat_bytes:fat_start+2*fat_bytes]:
            raise ValueError('FAT mirrors differ with mirroring enabled')
        self.base = (reserved+fats*fat_sectors)*self.bps
        self.cluster_bytes = self.bps*self.spc
        self.clusters = (len(self.data)-self.base)//self.cluster_bytes
        if (self.clusters+2)*4 > len(self.fat):
            raise ValueError('FAT too short for data area')
        self.free_bytes = sum(
            (struct.unpack_from('<I', self.fat, c*4)[0] & 0x0fffffff) == 0
            for c in range(2, self.clusters+2)
        )*self.cluster_bytes
        self.files = {}
        self.seen_directories = set()
        self.directory(root)

    def chain(self, first):
        data, seen, current = bytearray(), set(), first
        while current < 0x0ffffff8:
            if not 2 <= current < self.clusters+2 or current in seen:
                raise ValueError('Invalid/cyclic FAT chain')
            seen.add(current)
            pos = self.base+(current-2)*self.cluster_bytes
            data += self.data[pos:pos+self.cluster_bytes]
            current = struct.unpack_from('<I', self.fat, current*4)[0] & 0x0fffffff
        return bytes(data)

    def directory(self, first, parent='', depth=0):
        if depth > 15 or first in self.seen_directories:
            raise ValueError('Invalid directory graph')
        self.seen_directories.add(first)
        raw, long_name = self.chain(first), []
        for pos in range(0, len(raw), 32):
            item = raw[pos:pos+32]
            if item[0] == 0:
                break
            if item[0] == 0xe5:
                long_name = []
                continue
            attr = item[11]
            if attr == 15:
                long_name.append((item[0] & 31, item[1:11]+item[14:26]+item[28:32]))
                continue
            name = item[:8].decode('ascii', errors='replace').rstrip()
            ext = item[8:11].decode('ascii', errors='replace').rstrip()
            name += ('.'+ext) if ext else ''
            if long_name:
                name = b''.join(v for _, v in sorted(long_name)).decode('utf-16-le').split('\0')[0].rstrip('\uffff')
            long_name = []
            if name in ('.', '..') or attr & 8:
                continue
            first_cluster = (struct.unpack_from('<H', item, 20)[0] << 16) | struct.unpack_from('<H', item, 26)[0]
            path = parent+'/'+name
            if path.casefold() in self.files:
                raise ValueError('Duplicate FAT filename')
            self.files[path.casefold()] = {
                'path': path, 'cluster': first_cluster,
                'bytes': struct.unpack_from('<I', item, 28)[0], 'directory': bool(attr & 16),
            }
            if attr & 16:
                self.directory(first_cluster, path, depth+1)

    def read(self, path):
        item = self.files[path.casefold()]
        if item['directory']:
            raise ValueError('Expected a file')
        data = self.chain(item['cluster']) if item['bytes'] else b''
        if len(data) < item['bytes']:
            raise ValueError('Truncated FAT file')
        return data[:item['bytes']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    stamp = datetime.now(TZ).strftime('%Y%m%d-%H%M%S')
    out = (args.output or ROOT/f'evidence/nabu-xnu-preflight-{stamp}').resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {
        'status': 'in_progress', 'started_at': datetime.now(TZ).isoformat(),
        'serial': backup.SERIAL, 'checks': {}, 'tablet_operations': 'read-only',
        'installed': False, 'rebooted': False, 'partition_writes': False,
        'full_image_hashes': 'not calculated; exact sizes and GPT CRCs checked',
    }

    def save():
        (out/'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

    def check(name, passed):
        report['checks'][name] = bool(passed)
        if not passed:
            raise ValueError(name)

    save()
    try:
        identity = {p: backup.text_command('getprop '+p) for p in (
            'ro.product.device', 'ro.product.model', 'ro.serialno',
            'ro.boot.slot_suffix', 'sys.boot_completed', 'ro.build.fingerprint',
        )}
        report['identity'] = identity
        check('identity', identity['ro.product.device'] == 'nabu'
              and identity['ro.product.model'] == '21051182C'
              and identity['ro.serialno'] == backup.SERIAL
              and identity['ro.boot.slot_suffix'] == '_a'
              and identity['sys.boot_completed'] == '1')
        check('root', backup.text_command('id').startswith('uid=0(root)'))
        mounts = backup.text_command('cat /proc/mounts')
        (out/'mounts-before.txt').write_text(mounts+'\n', encoding='utf-8')
        mounted_esp = []
        for line in mounts.splitlines():
            source = line.split()[0]
            if source.startswith('/dev/') and backup.text_command('readlink -f '+source) == '/dev/block/sda31':
                mounted_esp.append(line)
        check('esp_unmounted', not mounted_esp)
        check('esp_alias', backup.text_command('readlink -f /dev/block/by-name/esp') == '/dev/block/sda31')
        check('esp_size', backup.text_command('blockdev --getsize64 /dev/block/by-name/esp') == '350105600')
        for tool in 'cmp cp mv sync mount umount sha256sum sort uniq wc grep tr df tail awk basename rmdir'.split():
            check('tool_'+tool, bool(backup.text_command('command -v '+tool)))
        report['battery'] = backup.text_command('dumpsys battery')
        report['uptime'] = backup.text_command('cat /proc/uptime')
        report['kernel_cached_sda32_present'] = backup.text_command('[ ! -e /sys/class/block/sda32 ] || echo present') == 'present'

        recovery_manifest = json.loads((RECOVERY/'manifest.json').read_text(encoding='utf-8'))
        check('historical_recovery_complete', recovery_manifest['status'] == 'complete'
              and all((RECOVERY/x['file']).stat().st_size == x['bytes'] for x in recovery_manifest['files']))
        gpts = {}
        for disk, size in backup.EXPECTED_DISKS.items():
            check(disk+'_geometry', int(backup.text_command(f'blockdev --getsize64 /dev/block/{disk}')) == size
                  and backup.text_command(f'blockdev --getss /dev/block/{disk}') == '4096')
            info = backup.inspect_gpt(disk)
            gpts[disk] = info
            expected = json.loads((REMOVAL/'gpt-after.json').read_text()) if disk == 'sda' else recovery_manifest['gpt'][disk]
            check(disk+'_gpt_matches_known_state', info == expected)
            p, b = info['primary_header'], info['backup_header']
            blocks = (p['entry_count']*p['entry_size']+4095)//4096
            ranges = [('primary', 0, p['entries_lba']+blocks),
                      ('backup', b['entries_lba'], size//4096-b['entries_lba'])]
            for label, start, count in ranges:
                data = backup.read_blocks(disk, start, count)
                (out/f'{disk}-gpt-{label}.bin').write_bytes(data)
                previous = REMOVAL/f'sda-gpt-{label}-after.bin' if disk == 'sda' else RECOVERY/f'{disk}-gpt-{label}.bin'
                check(f'{disk}_{label}_byte_identical', data == previous.read_bytes())
        (out/'gpt-current.json').write_text(json.dumps(gpts, indent=2)+'\n')
        parts = gpts['sda']['partitions']
        check('64gb_remains_unallocated', not any(p['first_lba'] <= 18364746 and p['last_lba'] >= 2739747 for p in parts))
        check('partition_32_absent_from_gpt', not any(p['number'] == 32 for p in parts))
        report['unallocated'] = {'first_lba': 2739747, 'last_lba': 18364746, 'bytes': 64000000000}
        report['gpt_verified_luns'] = list(gpts)
        print('Identity and all six GPTs verified; 64 GB remains unallocated.', flush=True)

        archive = BUNDLE/'nabu-offline-candidate-20261022.zip'
        extracted = out/'bundle'
        check('documented_release_archive_size', archive.stat().st_size == 13248407)
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            check('documented_release_member_count', len(names) == 111)
            check('archive_names_safe_unique', len(names) == len(set(names)) and all(
                not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts
                and '\\' not in n and ':' not in n for n in names))
            check('archive_crc', z.testzip() is None)
            check('archive_matches_workspace', all(z.read(n) == (BUNDLE/n).read_bytes() for n in names))
            z.extractall(extracted)
        result = subprocess.run(['py', '-3.14', str(extracted/'verify_bundle.py')], capture_output=True, text=True, check=True)
        bundle_verification = json.loads(result.stdout)
        (out/'verify-bundle.json').write_text(result.stdout)
        check('extracted_bundle_verified', bundle_verification['passed'] and bundle_verification['include_el0'])
        report['bundle'] = {'archive': str(archive), 'bytes': archive.stat().st_size, 'members': len(names), 'extracted': str(extracted)}
        check('pc_backup_space', shutil.disk_usage(out).free > 350105600+1024**3)
        report['esp_backup'] = backup.copy_device('/dev/block/by-name/esp', 350105600, out/'esp-before-xnu.img')
        fat = FatImage(out/'esp-before-xnu.img')
        report['esp_free_bytes'] = fat.free_bytes
        check('esp_free_at_least_100mib', fat.free_bytes >= 100*1024**2)
        (out/'esp-filelist.json').write_text(json.dumps(list(fat.files.values()), indent=2)+'\n')
        for rel in ('NabuStage1.efi', 'UniXNU.efi', 'Drivers/DarwinBoot.efi'):
            check('existing_efi_'+rel, fat.read('/EFI/UniXNU/'+rel) == (extracted/'staged_esp/EFI/UniXNU'/rel).read_bytes())
        refind = fat.read('/EFI/Boot/refind.conf')
        check('refind_matches_post_removal', refind == (REMOVAL/'refind.installed.conf').read_bytes())
        check('refind_android_default', b'default_selection "Android"' in refind)
        check('refind_ubuntu_hidden', b'dont_scan_dirs + EFI/ubuntu' in refind)
        check('refind_loader_entry', b'loader \\EFI\\UniXNU\\NabuStage1.efi' in refind)
        check('android_efi_unchanged', fat.read('/EFI/android/AndroidBootPkg.efi') == (REMOVAL/'AndroidBootPkg.before.efi').read_bytes())
        for rel in ('EFI/Boot/refind.conf', 'EFI/UniXNU/unixnu.toml', 'EFI/UniXNU/stage1-report.txt'):
            (out/Path(rel).name).write_bytes(fat.read('/'+rel))
        check('gpts_stable_after_backup', all(backup.inspect_gpt(disk) == info for disk, info in gpts.items()))
        check('mounts_unchanged', backup.text_command('cat /proc/mounts') == mounts)
        report['status'] = 'prepared_not_installed'
        report['next_step'] = ('Verify normal default Android boot after GPT change, then rerun this preflight'
                               if report['kernel_cached_sda32_present']
                               else 'Install only while the checked device state and bundle still apply')
        report['passed'] = True
        report['finished_at'] = datetime.now(TZ).isoformat()
        save()
        print(json.dumps({'passed': True, 'checks': len(report['checks']), 'esp_free_bytes': fat.free_bytes,
                          'backup': str(out/'esp-before-xnu.img'), 'result': str(out/'result.json'),
                          'installed': False, 'rebooted': False}, indent=2), flush=True)
    except BaseException as error:
        report.update(status='failed', passed=False, error=str(error))
        save()
        raise


if __name__ == '__main__':
    main()
