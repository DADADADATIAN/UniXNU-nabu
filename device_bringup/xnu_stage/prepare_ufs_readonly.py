#!/usr/bin/env python3
"""Prepare/verify a source-built UFS overlay entirely offline; never install it."""
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
from test_nabu_qemu import patch_adt_for_qemu_virt_gic, ufs_readonly_gate_checks
from make_nabu_ufs_adt import ufs_tree
from collect_outputs import macho_summary
from prepare_source import INPUT_SHA256, UPSTREAM

MODES = ('disabled', 'invalid-resources', 'unavailable-clocks')
BOOT_ARGS = '-v serial=3 debug=0x14e kt_fixed_zones=120 cpus=1 nabu-source-text=1'
REQUIRED_CHECKS = ('darwinboot_inputs_validated', 'darwinboot_owned_1gib', 'no_boot_refusal',
                   'no_uefi_assert', 'native_4k_page_size', 'armdt_platform_configured',
                   'armcpu_gic_ready', 'armcpu_timer_irq_delivered', 'kernel_no_panic',
                   'original_apfs_registered', 'original_apfs_vfsops_owned')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode('utf-8')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def resource_adt(wrong_stream=False):
    tree = ufs_tree()
    if wrong_stream:
        node = next(n for n in next(n for n in tree.children if n.name == 'arm-io').children if n.name == 'ufs')
        next(p for p in node.properties if p.key == 'nabu,ufs-stream').data = (0x301).to_bytes(4, 'little')
    return tree.serialize()


def append_entries(source, run_id):
    menu = tomllib.loads(source.decode('utf-8'))
    entries = menu.get('entry', [])
    ids = [e.get('id') for e in entries]
    require(ids and all(isinstance(i, str) for i in ids) and len(set(ids)) == len(ids), 'Invalid baseline menu IDs')
    require(menu.get('boot', {}).get('default') == 'return', 'Baseline must default to Return')
    require(any(e.get('id') == 'return' and e.get('type') == 'action' and e.get('action') == 'exit' for e in entries),
            'Baseline Return entry is not an exit action')
    kernel = f'Payloads/kernel-nabu-ufs-readonly-{run_id}.macho'
    require(not any(str(e.get('path', '')).casefold() == kernel.casefold() for e in entries), 'Payload path already in menu')
    added = []
    result = source
    for mode, title, extra in (('disabled', 'UFS source candidate - hardware disabled', ''),
                                ('read', 'UFS LUN0 read-only - hardware opt-in', ' native-ufs-readonly=1')):
        item = dict(id=f'nabu-ufs-{mode}-{run_id}', title=title, type='xnu', path=kernel, args=BOOT_ARGS + extra)
        require(item['id'] not in ids, 'UFS menu entry already exists')
        result += ('\n\n[[entry]]\n' + ''.join(f'{key} = {json.dumps(value)}\n' for key, value in item.items())).encode('ascii')
        added.append(item)
    parsed = tomllib.loads(result.decode('utf-8'))
    require(parsed['entry'] == entries + added, 'Existing menu entries changed')
    before, after = dict(menu), dict(parsed)
    before.pop('entry'); after.pop('entry')
    require(before == after, 'Existing menu settings changed')
    return result, kernel, added


def validate_inputs(summary, source_manifest, kernel, prelink, abi, adt, reports, loaders):
    run = summary.get('run_id')
    require(type(run) is int and run > 0, 'Missing actual Actions run ID')
    require(re.fullmatch('[0-9a-f]{40}', summary.get('head_sha', '')), 'Missing actual source head SHA')
    require(set(loaders) == {'unixnu', 'darwinboot'} and all(re.fullmatch('[0-9a-f]{64}', value) for value in loaders.values()),
            'Both required loader hashes must be retained')
    for key, expected in (('profile', 'nabu_ufs_readonly_defconfig'), ('upstream_commit', UPSTREAM),
                          ('inputs_release', 'unixnu-source-inputs'), ('inputs_asset', 'ipsw-21h16-small.zip'),
                          ('inputs_sha256', INPUT_SHA256), ('build_step_outcome', 'success'),
                          ('input_verified', True), ('candidate_validated', True), ('ufs_abi_validated', True),
                          ('ufs_read_only', True), ('undefined_symbol_count', 0)):
        require(summary.get(key) == expected, 'Unexpected CI identity/qualification: ' + key)
    for key in ('run_id', 'run_attempt', 'head_sha', 'profile', 'inputs_sha256'):
        require(source_manifest.get(key) == summary.get(key), 'Private source identity mismatch: ' + key)
    require(summary.get('candidate_sha256') == digest(kernel) == prelink.get('candidate_sha256'), 'Candidate hash mismatch')
    require(summary.get('candidate_bytes') == len(kernel), 'Candidate length mismatch')
    require(prelink.get('slide') == -0x1360000 and
            prelink.get('original_sha256') == 'f7d1952c7a21633d212eccf288e77444fff0cc86976db5de292f6819c2ffa1b2',
            'Unexpected original 21H16 prelink contract')
    require({'com.apple.filesystems.apfs', 'com.apple.kec.corecrypto'} <= set(prelink.get('components', [])), 'Missing original component closure')
    require(abi.get('readonly_abi') == 1 and abi.get('linked_block_slots_checked') == 190, 'Missing final UFS ABI qualification')
    require(adt == resource_adt(), 'ADT is not the exact nabu physical resource description')
    require(set(reports) == set(MODES), 'All three QEMU gate observations are required')
    for mode, report in reports.items():
        require(report.get('ufs_readonly_gate_required') == mode and report.get('passed') is True, 'Wrong/failed QEMU case: ' + mode)
        require(report.get('qemu_virt_gic_override') is True and report.get('real_xnu_on_nabu_hardware') is False and
                report.get('crypto_provider') == 'original-prelinked-native', 'Wrong QEMU platform/provider scope: ' + mode)
        hashes = report.get('input_sha256', {})
        require(hashes.get('kernel') == digest(kernel) and hashes.get('prelink_report') == digest(encoded(prelink)), 'QEMU candidate/prelink mismatch: ' + mode)
        for name, expected_hash in loaders.items():
            require(hashes.get(name) == expected_hash, 'QEMU loader mismatch: ' + name)
        case_adt = resource_adt(mode == 'invalid-resources')
        require(hashes.get('adt') == digest(case_adt), 'QEMU resource input mismatch: ' + mode)
        require(report.get('staged_adt_sha256') == digest(patch_adt_for_qemu_virt_gic(case_adt)), 'QEMU staged tree mismatch: ' + mode)
        state, checks = report.get('gdb_globals', {}), report.get('checks', {})
        require(all(checks.get(name) is True for name in REQUIRED_CHECKS), 'Missing named boot observations: ' + mode)
        require(state.get('_panicstr') == 0 and (state.get('_armcpu_timer_interrupts') or 0) > 0, 'Live kernel observation failed: ' + mode)
        require(all(ufs_readonly_gate_checks(state, report.get('boot_args', ''), mode).values()), 'Raw UFS observation failed: ' + mode)
    return run


def prepare(ci, menu, adt, reports, unixnu, darwinboot, output):
    ci, output = ci.resolve(), output.resolve()
    require(not output.exists(), 'Output must be a new directory')
    require(not output.is_relative_to(ci), 'Output must be outside the CI evidence directory')
    extracted = ci / 'extracted'
    kernel = (extracted / 'outputs/kernel/kernel.macho').read_bytes()
    prelink_bytes = (extracted / 'outputs/kernel/kernel.json').read_bytes()
    summary = read_json(ci / 'summary/summary.json')
    manifest = read_json(extracted / 'source-manifest.json')
    abi_path = 'outputs/tree/build/native-ufs/candidate-bindings.json'
    blobs = {
        'outputs/kernel/kernel.macho': kernel,
        'outputs/kernel/kernel.json': prelink_bytes,
        abi_path: (extracted / abi_path).read_bytes(),
    }
    for name, data in blobs.items():
        require(manifest.get('files', {}).get(name, {}).get('sha256') == digest(data), 'Private artifact hash mismatch: ' + name)
    loaders = {'unixnu': digest(unixnu.read_bytes()), 'darwinboot': digest(darwinboot.read_bytes())}
    raw_reports = {mode: reports[mode].read_bytes() for mode in MODES}
    parsed_reports = {mode: json.loads(raw_reports[mode]) for mode in MODES}
    prelink = json.loads(prelink_bytes)
    # Bind to the actual prelink bytes, including its original formatting.
    require(prelink_bytes == encoded(prelink), 'Unexpected prelink report encoding')
    adt_bytes = adt.read_bytes()
    run = validate_inputs(summary, manifest, kernel, prelink, json.loads(blobs[abi_path]), adt_bytes, parsed_reports, loaders)
    require(not macho_summary(extracted / 'outputs/kernel/kernel.macho')['undefined_names'], 'Kernel still has undefined symbols')
    source_menu = menu.read_bytes()
    new_menu, payload, added = append_entries(source_menu, run)
    files = {payload: kernel, payload + '.adt': adt_bytes, 'unixnu.toml': new_menu,
             'evidence/menu-source.toml': source_menu, 'evidence/ci-summary.json': encoded(summary),
             'evidence/prelink-report.json': prelink_bytes, 'evidence/ufs-abi.json': blobs[abi_path],
             'evidence/source-manifest.json': (extracted / 'source-manifest.json').read_bytes()}
    files.update({'evidence/qemu-' + mode + '.json': raw_reports[mode] for mode in MODES})
    record = dict(schema=1, run_id=run, head_sha=summary['head_sha'], profile=summary['profile'],
                  input_release=summary['inputs_release'], input_asset=summary['inputs_asset'], input_sha256=INPUT_SHA256,
                  base_menu_sha256=digest(source_menu), required_loaders=loaders,
                  added_entries=added, files={name: dict(bytes=len(data), sha256=digest(data)) for name, data in files.items()},
                  overlay_files=['unixnu.toml', payload, payload + '.adt'],
                  minimum_additional_payload_bytes=len(kernel) + len(adt_bytes) + len(new_menu),
                  tablet_written=False, hardware_tested=False,
                  next_observation='Actual SM8150 GCC/HC accessibility, queue/SMMU adoption, LUN capacity and known disk bytes',
                  installation_gate='Compare current menu and loader bytes with this snapshot, check actual device and free ESP space, then obtain covered write/boot authorization')
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (output / 'manifest.json').write_bytes(encoded(record))
    return verify(output)


def verify(package):
    require(not package.is_symlink(), 'Package cannot be a link')
    package = package.resolve()
    record = read_json(package / 'manifest.json')
    require(record.get('schema') == 1 and record.get('tablet_written') is False and record.get('hardware_tested') is False, 'Invalid offline package scope')
    seen = set()
    for name, expected in record['files'].items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and '\\' not in name, 'Invalid package path')
        require(name.casefold() not in seen, 'Case-colliding package path')
        seen.add(name.casefold())
        target = package / path
        require(not target.is_symlink() and target.resolve().is_relative_to(package), 'Linked/escaping package file')
        data = target.read_bytes()
        require(len(data) == expected['bytes'] and digest(data) == expected['sha256'], 'Changed package file: ' + name)
    actual = {str(p.relative_to(package)).replace('\\', '/') for p in package.rglob('*') if p.is_file()}
    require(actual == set(record['files']) | {'manifest.json'}, 'Unclassified files in package')
    source = (package / 'evidence/menu-source.toml').read_bytes()
    require(digest(source) == record['base_menu_sha256'], 'Changed baseline menu binding')
    menu, payload, added = append_entries(source, record['run_id'])
    require(menu == (package / 'unixnu.toml').read_bytes() and added == record['added_entries'], 'Changed menu semantics')
    require(record['overlay_files'] == ['unixnu.toml', payload, payload + '.adt'], 'Unexpected installation scope')
    summary = read_json(package / 'evidence/ci-summary.json')
    prelink = read_json(package / 'evidence/prelink-report.json')
    require(summary.get('head_sha') == record['head_sha'] and summary.get('run_id') == record['run_id'], 'Changed run identity')
    require(record.get('profile') == summary.get('profile') and record.get('input_release') == summary.get('inputs_release') and
            record.get('input_asset') == summary.get('inputs_asset') and record.get('input_sha256') == INPUT_SHA256,
            'Changed package profile/input identity')
    require(digest((package / payload).read_bytes()) == summary['candidate_sha256'] == prelink['candidate_sha256'], 'Changed candidate binding')
    require((package / (payload + '.adt')).read_bytes() == resource_adt(), 'Changed physical ADT')
    private = read_json(package / 'evidence/source-manifest.json')
    abi = read_json(package / 'evidence/ufs-abi.json')
    kernel_bytes = (package / payload).read_bytes()
    for relative, data in (('outputs/kernel/kernel.macho', kernel_bytes),
                           ('outputs/kernel/kernel.json', (package / 'evidence/prelink-report.json').read_bytes()),
                           ('outputs/tree/build/native-ufs/candidate-bindings.json', (package / 'evidence/ufs-abi.json').read_bytes())):
        require(private.get('files', {}).get(relative, {}).get('sha256') == digest(data), 'Changed original artifact binding: ' + relative)
    reports = {mode: read_json(package / ('evidence/qemu-' + mode + '.json')) for mode in MODES}
    validate_inputs(summary, private, kernel_bytes, prelink, abi, resource_adt(), reports, record['required_loaders'])
    return dict(package=str(package), run_id=record['run_id'], head_sha=record['head_sha'],
                files_verified=len(record['files']), tablet_written=False, hardware_tested=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('verify'); check.add_argument('package', type=Path)
    create = sub.add_parser('prepare')
    for name in ('ci', 'menu', 'adt', 'unixnu', 'darwinboot', 'output'):
        create.add_argument('--' + name, type=Path, required=True)
    for mode in MODES:
        create.add_argument('--qemu-' + mode, type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'verify':
        result = verify(args.package)
    else:
        reports = {mode: getattr(args, 'qemu_' + mode.replace('-', '_')) for mode in MODES}
        result = prepare(args.ci, args.menu, args.adt, reports, args.unixnu, args.darwinboot, args.output)
    print(json.dumps(result, indent=2))
