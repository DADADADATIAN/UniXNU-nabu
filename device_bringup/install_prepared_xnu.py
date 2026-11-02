"""Install an already verified nabu ESP overlay, then read back and verify it.

Requires a fresh post-reboot prepare_hardware_test.py directory. Uses the
reviewed on-device installer and its file backup; never reboots or writes GPT.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import time
import zipfile

import backup_recovery as backup
from prepare_hardware_test import FatImage, ROOT, BUNDLE, TZ


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', type=Path, required=True)
    parser.add_argument('--apply', action='store_true', required=True)
    args = parser.parse_args()
    out = args.preflight.resolve()
    if not out.is_relative_to(ROOT/'evidence'):
        raise SystemExit('Expected a project evidence directory')
    result_path = out/'installation-result.json'
    if result_path.exists():
        raise SystemExit('Installation record exists; inspect instead of repeating')
    pre = json.loads((out/'result.json').read_text(encoding='utf-8'))
    elapsed = (datetime.now(TZ)-datetime.fromisoformat(pre['finished_at'])).total_seconds()
    if not (pre['passed'] and all(pre['checks'].values()) and not pre['kernel_cached_sda32_present']
            and 0 <= elapsed <= 600 and (out/'esp-before-xnu.img').stat().st_size == 350105600):
        raise SystemExit('Need a fresh successful post-reboot preflight and current ESP backup')
    bundle = out/'bundle'
    stamp = datetime.now(TZ).strftime('%Y%m%d-%H%M%S')
    remote = '/data/local/tmp/unixnu-xnu-stage-'+stamp
    report = {
        'status': 'prechecking', 'started_at': datetime.now(TZ).isoformat(),
        'serial': backup.SERIAL, 'preflight': str(out/'result.json'),
        'remote_stage': remote, 'checks': {}, 'commands': [],
        'rebooted': False, 'partition_layout_writes': False,
        'android_temporary_files': remote,
    }

    def save():
        result_path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

    def check(name, value):
        report['checks'][name] = bool(value)
        if not value:
            raise ValueError(name)

    def adb_step(label, *args):
        started = time.monotonic()
        result = subprocess.run(['adb', '-s', backup.SERIAL, *args], capture_output=True, timeout=300)
        (out/(label+'.stdout.txt')).write_bytes(result.stdout)
        (out/(label+'.stderr.txt')).write_bytes(result.stderr)
        report['commands'].append({'step': label, 'exit_code': result.returncode,
                                   'elapsed_seconds': round(time.monotonic()-started, 2)})
        save()
        print(label+': '+str(result.returncode), flush=True)
        if result.returncode:
            print(result.stdout.decode(errors='replace'), flush=True)
            print(result.stderr.decode(errors='replace'), flush=True)
            raise RuntimeError(label+' failed; preserve logs and inspect device state')
        return result.stdout

    save()
    try:
        with zipfile.ZipFile(BUNDLE/'nabu-offline-candidate-20261022.zip') as z:
            check('extracted_members_unchanged', all((bundle/n).read_bytes() == z.read(n) for n in z.namelist()))
        result = subprocess.run(['py', '-3.14', str(bundle/'verify_bundle.py')], capture_output=True, check=True)
        check('bundle_reverified', json.loads(result.stdout)['passed'])
        check('device_identity', backup.text_command('getprop ro.serialno') == backup.SERIAL
              and backup.text_command('getprop ro.product.device') == 'nabu'
              and backup.text_command('getprop ro.boot.slot_suffix') == '_a'
              and backup.text_command('getprop sys.boot_completed') == '1'
              and backup.text_command('id').startswith('uid=0(root)'))
        check('partition_cache_refreshed', backup.text_command('[ ! -e /sys/class/block/sda32 ] || echo present') == '')
        check('same_android_boot', float(backup.text_command('cat /proc/uptime').split()[0]) >= float(pre['uptime'].split()[0]))
        gpts = json.loads((out/'gpt-current.json').read_text())
        check('gpt_matches_preflight', all(backup.inspect_gpt(disk) == value for disk, value in gpts.items()))
        report['status'] = 'installing'
        save()
        adb_step('mkdir-stage', 'shell', 'mkdir', '-p', remote+'/files')
        overlay = bundle/'staged_esp/EFI/UniXNU'
        adb_step('push-payloads', 'push', str(overlay)+'/.', remote+'/files/')
        helpers = ('install_xnu_stage.sh', 'restore_xnu_stage.sh', 'install-files.txt', 'transfer-checksums.txt')
        adb_step('push-helpers', 'push', *(str(bundle/n) for n in helpers), remote+'/')
        output = adb_step('installation', 'shell', 'su', '-c', f'sh {remote}/install_xnu_stage.sh {remote}')
        print(output.decode(errors='replace'), flush=True)
        check('installer_complete_marker', b'XNU_STAGE_INSTALLED' in output.splitlines())
        report['status'] = 'installed_verifying'
        save()
        relative = backup.text_command(f'cat {remote}/installed-backup-path.txt')
        expected_relative = 'EFI/UniXNU/backups/xnu-unixnu-xnu-stage-'+stamp
        check('backup_path_matches_this_installation', relative == expected_relative)
        (out/'installed-backup-path.txt').write_text(relative+'\n')
        report['esp_backup_relative_path'] = relative
        report['restore_command'] = f'adb -s {backup.SERIAL} shell su -c "sh {remote}/restore_xnu_stage.sh {remote} {relative}"'
        save()

        report['after_esp_snapshot'] = backup.copy_device('/dev/block/by-name/esp', 350105600, out/'esp-after-xnu.img')
        before, after = FatImage(out/'esp-before-xnu.img'), FatImage(out/'esp-after-xnu.img')
        install_list = (bundle/'install-files.txt').read_text(encoding='ascii').splitlines()
        for rel in install_list+['unixnu.toml', 'NabuStage1.efi', 'UniXNU.efi', 'Drivers/DarwinBoot.efi']:
            check('installed_'+rel, after.read('/EFI/UniXNU/'+rel) == (overlay/rel).read_bytes())
        check('refind_preserved', after.read('/EFI/Boot/refind.conf') == before.read('/EFI/Boot/refind.conf'))
        check('android_efi_preserved', after.read('/EFI/android/AndroidBootPkg.efi') == before.read('/EFI/android/AndroidBootPkg.efi'))
        check('old_menu_backed_up', after.read('/'+relative+'/original/unixnu.toml') == before.read('/EFI/UniXNU/unixnu.toml'))
        check('refind_backed_up', after.read('/'+relative+'/refind.before.conf') == before.read('/EFI/Boot/refind.conf'))
        absent = after.read('/'+relative+'/absent-files.txt').decode('ascii').splitlines()
        for rel in install_list:
            path = '/EFI/UniXNU/'+rel
            if path.casefold() in before.files:
                check('backup_'+rel, after.read('/'+relative+'/original/'+rel) == before.read(path))
            else:
                check('recorded_absent_'+rel, rel in absent)
        changed = {('/EFI/UniXNU/'+rel).casefold() for rel in install_list+['unixnu.toml']}
        retained = [v['path'] for k, v in before.files.items() if not v['directory'] and k not in changed]
        check('all_other_existing_files_preserved', all(after.read(p) == before.read(p) for p in retained))
        expected_new = {('/EFI/UniXNU/'+rel).casefold() for rel in install_list}
        new_files = [k for k, v in after.files.items() if k not in before.files and not v['directory']]
        check('new_files_within_expected_scope', all(k in expected_new or k.startswith('/'+relative.casefold()+'/') for k in new_files))
        report['retained_files_verified'] = len(retained)
        report['new_files'] = new_files
        report['esp_free_bytes_after'] = after.free_bytes
        gpts_after = {disk: backup.inspect_gpt(disk) for disk in gpts}
        check('all_six_gpts_unchanged_after_installation', gpts_after == gpts)
        (out/'gpt-after-installation.json').write_text(json.dumps(gpts_after, indent=2)+'\n')
        mounts = backup.text_command('cat /proc/mounts')
        check('installer_mounts_cleaned_up', remote+'/esp' not in mounts)
        check('android_still_running', backup.text_command('getprop sys.boot_completed') == '1')
        report['status'] = 'installed_verified_not_boot_tested'
        report['passed'] = True
        report['hardware_xnu_tested'] = False
        report['finished_at'] = datetime.now(TZ).isoformat()
        save()
        print(json.dumps({'passed': True, 'checks': len(report['checks']), 'status': report['status'],
                          'result': str(result_path), 'restore_command': report['restore_command']}, indent=2), flush=True)
    except BaseException as error:
        report.update(status='failed_inspect_logs', passed=False, error=str(error))
        save()
        raise


if __name__ == '__main__':
    main()
