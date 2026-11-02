#!/usr/bin/env python3
"""Prepare/verify the merged hardware UFS root payload entirely offline.

The package installs one XNU candidate (UFS root windows + original userland
closure), its ADT, the static trust cache sidecar, and a menu that keeps Return,
Hello and the V5 fallback. All other diagnostic payloads are deleted only by the
on-device installer after the user authorizes the write.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'device_bringup'))
sys.path.insert(0, str(ROOT / 'device_bringup/adt'))
sys.path.insert(0, str(ROOT / 'source-ci'))
from collect_outputs import macho_summary
from make_nabu_ufs_adt import ROOT_VOLUME_UUID, ufs_tree

BOOT_ARGS = ('-v serial=3 debug=0x14e kt_fixed_zones=120 cpus=1 nabu-source-text=1 '
             'native-ufs-root=1 native-ufs-diagnostics=1 '
             'native-ufs-os-lba=2739968 native-ufs-os-sectors=11718723 '
             'native-ufs-systemos-lba=4204809 native-ufs-systemos-sectors=6451200')
KEEP_IDS = ('return', 'hello', 'nabu-xnu-source-g0')
NEW_ID = 'nabu-ufs-root'
NEW_NAME = 'kernel-nabu-ufs-root.macho'
NEW_TITLE = 'iPadOS UFS root - original launchd'


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode('utf-8')


def menu_blocks(source):
    parts = source.decode('utf-8').split('[[entry]]')
    require(len(parts) >= 2, 'Menu has no entries')
    return parts[0], parts[1:]


def block_id(block):
    match = re.search(r'^id = "([^"]+)"', block, re.M)
    require(match, 'Entry has no id')
    return match.group(1)


def block_paths(block):
    paths = []
    for key in ('path', 'initrd'):
        match = re.search(r'^' + key + r' = "([^"]+)"', block, re.M)
        if match:
            paths.append(match.group(1))
    return paths


def build_menu(source):
    prefix, blocks = menu_blocks(source)
    kept, removed = [], []
    for block in blocks:
        (kept if block_id(block) in KEEP_IDS else removed).append(block)
    require(any(block_id(b) == 'nabu-xnu-source-g0' for b in kept), 'V5 fallback entry is missing')
    new_block = (
        '\nid = ' + json.dumps(NEW_ID) + '\n'
        'title = ' + json.dumps(NEW_TITLE) + '\n'
        'type = "xnu"\n'
        'path = "Payloads/' + NEW_NAME + '"\n'
        'args = ' + json.dumps(BOOT_ARGS) + '\n')
    # Keep Return/Hello first, add the new entry, keep V5 last.
    ordered = [b for b in kept if block_id(b) != 'nabu-xnu-source-g0']
    ordered += [new_block]
    ordered += [b for b in kept if block_id(b) == 'nabu-xnu-source-g0']
    result = prefix + ''.join('[[entry]]' + b for b in ordered)
    parsed = tomllib.loads(result)
    require([e['id'] for e in parsed['entry']] ==
            [block_id(b) for b in ordered], 'Generated menu does not round-trip')
    require(parsed['boot']['default'] == 'return', 'Generated menu must default to Return')
    removed_paths = {p for block in removed for p in block_paths(block)}
    # Orphaned initrd from the replaced UFS-inspect entry; no kept entry uses it.
    extra = {'Payloads/launchd-ufs-inspect.macho'}
    sidecars = {p + suffix for p in removed_paths if p.endswith('.macho')
                for suffix in ('.adt', '.trustcache')}
    for path in extra:
        require(not any(path in block_paths(b) for b in ordered),
                'A kept entry references the orphaned payload: ' + path)
    delete = sorted(removed_paths | sidecars | extra)
    for path in delete:
        require(not any(path in block_paths(b) for b in ordered),
                'A kept entry still references a deleted payload: ' + path)
    return result.encode('utf-8'), delete, [block_id(b) for b in removed]


def check_kernel(kernel_path, kernel, prelink):
    summary = macho_summary(kernel_path)
    require(not summary['undefined_names'], 'Kernel still has undefined symbols')
    report = json.loads(prelink)
    require(report.get('candidate_sha256') == digest(kernel), 'Prelink candidate hash mismatch')
    require(report.get('candidate_bytes') == len(kernel), 'Prelink candidate length mismatch')
    require(report.get('slide') == -0x1360000, 'Unexpected 21H16 prelink slide')
    components = set(report.get('components', []))
    required = {'com.apple.filesystems.apfs',
                'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib',
                'com.apple.driver.AppleMobileFileIntegrity'}
    require(required <= components, 'Missing original userland component closure: ' +
            ', '.join(sorted(required - components)))
    return report


def check_adt(adt):
    require(adt == ufs_tree().serialize(), 'ADT is not the exact hardware UFS root description')


def check_trustcache(trust):
    require(len(trust) > 64 and len(trust) % 4 == 0, 'Trust cache bundle has an invalid size')
    require(digest(trust) != digest(b'\0' * len(trust)), 'Trust cache bundle is empty')


def build_installer(files, delete, old_ufs, new_name, required_kb):
    delete_words = ' '.join(json.dumps(p) for p in delete)
    lines = [
        '#!/system/bin/sh',
        '# Install/restore the merged UFS root payload; never reboots.',
        'set -eu',
        'MODE=${1:?install or restore}',
        'STAGE=${2:?prepared directory}',
        'case "$MODE" in install|restore) ;; *) exit 2 ;; esac',
        'case "$STAGE" in /data/local/tmp/ufs-root-*) ;; *) exit 2 ;; esac',
        'MNT="$STAGE/esp"',
        'UNI="$MNT/EFI/UniXNU"',
        '[ "$(id -u)" = 0 ]',
        '[ "$(getprop ro.product.device)" = nabu ]',
        '[ "$(getprop sys.boot_completed)" = 1 ]',
        '[ "$(readlink -f /dev/block/by-name/esp)" = /dev/block/sda31 ]',
        '[ ! -L "$STAGE" ] && [ ! -L "$STAGE/files" ] && [ ! -L "$STAGE/original" ]',
        'for tool in cmp cp mv rm sync mount umount sha256sum df tail awk readlink wc tr cat rmdir mkdir dirname; do command -v "$tool" >/dev/null; done',
        'check_file() {',
        '    rel=$1',
        '    [ -f "$STAGE/$rel" ] && [ ! -L "$STAGE/$rel" ]',
        '    hash=$(awk -v path="$rel" \'$2==path {n++; value=$1} END {if(n==1) print value}\' "$STAGE/transfer-checksums.txt")',
        '    [ "${#hash}" = 64 ]',
        '    case "$hash" in *[!0-9a-f]*) exit 2 ;; esac',
        '    (cd "$STAGE"; printf \'%s  %s\\n\' "$hash" "$rel" | sha256sum -c -)',
        '}',
        'for rel in ' + ' '.join(json.dumps(f) for f in files) + '; do check_file "$rel"; done',
        '[ "$(wc -l < "$STAGE/transfer-checksums.txt" | tr -d \' \')" = ' + str(len(files)) + ' ]',
        '[ ! -L "$STAGE/files/Payloads" ] && [ ! -L "$STAGE/original/Payloads" ]',
        'if [ "$MODE" = install ]; then',
        '    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$(cat "$STAGE/expected-boot-id.txt")" ]',
        'fi',
        'while read -r source target rest; do',
        '    case "$source" in /dev/*) [ "$(readlink -f "$source")" != /dev/block/sda31 ] ;; esac',
        '    [ "$target" != "$MNT" ]',
        'done < /proc/mounts',
        '[ ! -L "$MNT" ]',
        'mkdir -p "$MNT"',
        'mounted=0; touched=0; committed=0',
        'restore_originals() {',
        '    rm -f ' + ' '.join('"$UNI/' + p + '"' for p in ('Payloads/' + new_name,
                                                              'Payloads/' + new_name + '.adt',
                                                              'Payloads/' + new_name + '.trustcache',
                                                              'unixnu.toml.ufs-new')) + ' || return 1',
    ]
    lines += [
        '    for rel in ' + delete_words + '; do',
        '        if [ -f "$STAGE/deleted/$rel" ]; then',
        '            cp "$STAGE/deleted/$rel" "$UNI/$rel" || return 1',
        '            cmp "$STAGE/deleted/$rel" "$UNI/$rel" || return 1',
        '        fi',
        '    done',
    ]
    for p in old_ufs:
        lines.append('    cp "$STAGE/original/' + p + '" "$UNI/' + p + '" || return 1')
        lines.append('    cmp "$STAGE/original/' + p + '" "$UNI/' + p + '" || return 1')
    lines += [
        '    cp "$STAGE/original/unixnu.toml" "$UNI/unixnu.toml.ufs-new" || return 1',
        '    cmp "$STAGE/original/unixnu.toml" "$UNI/unixnu.toml.ufs-new" || return 1',
        '    sync || return 1',
        '    mv "$UNI/unixnu.toml.ufs-new" "$UNI/unixnu.toml" || return 1',
        '    cmp "$STAGE/original/unixnu.toml" "$UNI/unixnu.toml" || return 1',
        '    sync || return 1',
        '}',
        'cleanup() {',
        '    result=$?',
        '    trap - EXIT HUP INT TERM',
        '    set +e',
        '    if [ "$mounted" = 1 ]; then',
        '        if [ "$MODE" = install ] && [ "$touched" = 1 ] && [ "$committed" = 0 ]; then',
        '            if restore_originals; then echo UFS_ROOT_ROLLED_BACK >&2; else echo UFS_ROOT_ROLLBACK_FAILED >&2; result=91; fi',
        '        fi',
        '        umount "$MNT" || result=92',
        '    fi',
        '    rmdir "$MNT" 2>/dev/null || true',
        '    exit "$result"',
        '}',
        'trap cleanup EXIT',
        'trap \'exit 130\' HUP INT TERM',
        'mount -t vfat -o rw,umask=0077 /dev/block/by-name/esp "$MNT"',
        'mounted=1',
        '[ "$(df -Pk "$MNT" | tail -n 1 | awk \'{print $2}\')" = "$(cat "$STAGE/expected-esp-kblocks.txt")" ]',
        '[ ! -L "$UNI" ] && [ ! -L "$UNI/Payloads" ]',
        'verify_fixed() {',
        '    [ "$(sha256sum "$UNI/UniXNU.efi" | awk \'{print $1}\')" = e81ec27427e0f2599bd753328c25d8c8bd99df0441d538a3fda608bba16d5e11 ]',
        '    [ "$(sha256sum "$UNI/Drivers/DarwinBoot.efi" | awk \'{print $1}\')" = ba93b2799583489f9c7662dc8e54a62d676ff337933c5982811aa37477c3e7e9 ]',
        '    [ "$(sha256sum "$MNT/EFI/Boot/refind.conf" | awk \'{print $1}\')" = "$(cat "$STAGE/expected-refind-sha256.txt")" ]',
        '}',
        'verify_fixed',
        'if [ "$MODE" = install ]; then',
        '    cmp "$STAGE/original/unixnu.toml" "$UNI/unixnu.toml"',
    ]
    for p in old_ufs:
        lines.append('    cmp "$STAGE/original/' + p + '" "$UNI/' + p + '"')
    lines.append('    touched=1')
    lines += [
        '    mkdir -p "$STAGE/deleted"',
        '    [ ! -L "$STAGE/deleted" ]',
        '    for rel in ' + delete_words + '; do',
        '        if [ -f "$UNI/$rel" ]; then',
        '            mkdir -p "$STAGE/deleted/$(dirname "$rel")"',
        '            cp "$UNI/$rel" "$STAGE/deleted/$rel"',
        '            cmp "$UNI/$rel" "$STAGE/deleted/$rel"',
        '        fi',
        '        rm -f "$UNI/$rel"',
        '    done',
    ]
    lines += [
        '    [ "$(df -Pk "$MNT" | tail -n 1 | awk \'{print $4}\')" -ge ' + str(required_kb) + ' ]',
        '    cp "$STAGE/files/Payloads/' + new_name + '" "$UNI/Payloads/' + new_name + '"',
        '    cmp "$STAGE/files/Payloads/' + new_name + '" "$UNI/Payloads/' + new_name + '"',
        '    cp "$STAGE/files/Payloads/' + new_name + '.adt" "$UNI/Payloads/' + new_name + '.adt"',
        '    cmp "$STAGE/files/Payloads/' + new_name + '.adt" "$UNI/Payloads/' + new_name + '.adt"',
        '    cp "$STAGE/files/Payloads/' + new_name + '.trustcache" "$UNI/Payloads/' + new_name + '.trustcache"',
        '    cmp "$STAGE/files/Payloads/' + new_name + '.trustcache" "$UNI/Payloads/' + new_name + '.trustcache"',
        '    cp "$STAGE/files/unixnu.toml" "$UNI/unixnu.toml.ufs-new"',
        '    cmp "$STAGE/files/unixnu.toml" "$UNI/unixnu.toml.ufs-new"',
        '    sync',
        '    mv "$UNI/unixnu.toml.ufs-new" "$UNI/unixnu.toml"',
        '    cmp "$STAGE/files/unixnu.toml" "$UNI/unixnu.toml"',
        'else',
        '    cmp "$STAGE/files/unixnu.toml" "$UNI/unixnu.toml"',
        '    cmp "$STAGE/files/Payloads/' + new_name + '" "$UNI/Payloads/' + new_name + '"',
        '    cmp "$STAGE/files/Payloads/' + new_name + '.adt" "$UNI/Payloads/' + new_name + '.adt"',
        '    cmp "$STAGE/files/Payloads/' + new_name + '.trustcache" "$UNI/Payloads/' + new_name + '.trustcache"',
        '    restore_originals',
        'fi',
        'verify_fixed',
        'sync',
        'umount "$MNT"',
        'mounted=0',
        'committed=1',
        'if [ "$MODE" = install ]; then echo UFS_ROOT_INSTALLED; else echo UFS_ROOT_RESTORED; fi',
    ]
    return '\n'.join(lines) + '\n'


def prepare(args):
    output = args.output.resolve()
    require(not output.exists(), 'Output must be a new directory')
    kernel = args.kernel.read_bytes()
    prelink = args.prelink.read_bytes()
    adt = args.adt.read_bytes()
    trust = args.trustcache.read_bytes()
    source_menu = args.menu.read_bytes()
    prelink_report = check_kernel(args.kernel, kernel, prelink)
    check_adt(adt)
    check_trustcache(trust)
    menu, delete, removed = build_menu(source_menu)
    loaders = {'unixnu': args.unixnu.read_bytes(), 'darwinboot': args.darwinboot.read_bytes()}
    for artifact in (args.current_ufs_kernel, args.current_ufs_adt):
        require(re.fullmatch(r'[A-Za-z0-9._-]+\.macho(\.adt)?', artifact.name),
                'Unexpected current UFS artifact name: ' + artifact.name)
    old_ufs = ['Payloads/' + args.current_ufs_kernel.name,
               'Payloads/' + args.current_ufs_adt.name]
    files = {
        'files/Payloads/' + NEW_NAME: kernel,
        'files/Payloads/' + NEW_NAME + '.adt': adt,
        'files/Payloads/' + NEW_NAME + '.trustcache': trust,
        'files/unixnu.toml': menu,
        'original/unixnu.toml': source_menu,
        'original/' + old_ufs[0]: args.current_ufs_kernel.read_bytes(),
        'original/' + old_ufs[1]: args.current_ufs_adt.read_bytes(),
        'expected-boot-id.txt': (args.boot_id + '\n').encode('ascii'),
        'expected-esp-kblocks.txt': (str(args.esp_kblocks) + '\n').encode('ascii'),
        'expected-refind-sha256.txt': (digest(args.refind_conf.read_bytes()) + '\n').encode('ascii'),
    }
    check_files = sorted(files)
    checksums = ''.join(f'{digest(files[name])}  {name}\n' for name in check_files)
    files['transfer-checksums.txt'] = checksums.encode('ascii')
    required_kb = (len(kernel) + len(adt) + len(trust) + 65535) // 1024 + 2048
    installer = build_installer(check_files, delete, old_ufs, NEW_NAME, required_kb)
    files['install.sh'] = installer.encode('ascii')
    record = {
        'schema': 1, 'profile': 'nabu_ufs_root_defconfig', 'run_id': args.run_id,
        'kernel_sha256': digest(kernel), 'kernel_bytes': len(kernel),
        'prelink_sha256': digest(prelink), 'adt_sha256': digest(adt),
        'prelink_components': prelink_report.get('components', []),
        'prelink_slide': prelink_report.get('slide'),
        'trustcache_sha256': digest(trust), 'trustcache_bytes': len(trust),
        'base_menu_sha256': digest(source_menu), 'menu_sha256': digest(menu),
        'removed_entry_ids': removed, 'deleted_payload_paths': delete,
        'kept_entry_ids': list(KEEP_IDS), 'new_entry_id': NEW_ID,
        'new_payload': 'Payloads/' + NEW_NAME, 'new_boot_args': BOOT_ARGS,
        'old_ufs_payloads': old_ufs, 'loaders': {k: digest(v) for k, v in loaders.items()},
        'expected_boot_id': args.boot_id, 'expected_esp_kblocks': args.esp_kblocks,
        'files': {name: {'bytes': len(data), 'sha256': digest(data)} for name, data in files.items()},
        'tablet_written': False, 'hardware_tested': False,
        'installation_gate': ('Re-run preflight on the connected tablet, verify boot ID/menu/ESP, '
                              'authorize write/receipt, then install and reboot with the user'),
    }
    output.mkdir(parents=True)
    for name, data in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (output / 'manifest.json').write_bytes(encoded(record))
    return verify(output)


def verify(package):
    package = package.resolve()
    record = json.loads((package / 'manifest.json').read_text(encoding='utf-8'))
    require(record['tablet_written'] is False and record['hardware_tested'] is False,
            'Package scope is not offline')
    seen = set()
    for name, expected in record['files'].items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and '\\' not in name,
                'Invalid package path')
        require(name.casefold() not in seen, 'Case-colliding package path')
        seen.add(name.casefold())
        data = (package / path).read_bytes()
        require(len(data) == expected['bytes'] and digest(data) == expected['sha256'],
                'Changed package file: ' + name)
    actual = {str(p.relative_to(package)).replace('\\', '/') for p in package.rglob('*') if p.is_file()}
    require(actual == set(record['files']) | {'manifest.json'}, 'Unclassified files in package')
    menu, delete, removed = build_menu((package / 'original/unixnu.toml').read_bytes())
    require(menu == (package / 'files/unixnu.toml').read_bytes(), 'Changed menu semantics')
    require(delete == record['deleted_payload_paths'] and removed == record['removed_entry_ids'],
            'Changed payload deletion set')
    require(record['kernel_sha256'] == digest((package / ('files/Payloads/' + NEW_NAME)).read_bytes()),
            'Changed new kernel')
    return {'package': str(package), 'files_verified': len(record['files']),
            'deleted_payloads': len(record['deleted_payload_paths']),
            'tablet_written': False, 'hardware_tested': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('verify')
    check.add_argument('package', type=Path)
    create = sub.add_parser('prepare')
    for name in ('kernel', 'prelink', 'adt', 'trustcache', 'menu', 'unixnu', 'darwinboot',
                 'refind-conf', 'current-ufs-kernel', 'current-ufs-adt', 'output'):
        create.add_argument('--' + name, type=Path, required=True)
    create.add_argument('--boot-id', required=True)
    create.add_argument('--esp-kblocks', type=int, required=True)
    create.add_argument('--run-id', default='local-ufs-root-20261025')
    args = parser.parse_args()
    result = verify(args.package) if args.command == 'verify' else prepare(args)
    print(json.dumps(result, indent=2))