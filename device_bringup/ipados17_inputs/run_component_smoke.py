#!/usr/bin/env python3
"""Reproduce original-component QEMU smoke tests and their expected failures.

Uses preserved local inputs; no compilation, network access or tablet operation.
The PID 1 fixture is self-authored. A passing smoke test is not an APFS mount
or an Apple launchd test. Raw harness failures remain failures in their reports.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / 'device_bringup/ipados17_inputs/system-17.7-21H16-20261023'
sys.path.insert(0, str(ROOT / 'device_bringup/adt'))
from make_nabu_adt import build_nabu_tree
from validate_adt import parse_adt, validate_adt_bytes


def prepare_adt(original, destination):
    data = original.read_bytes()
    tree = parse_adt(data)
    chosen = tree.find_node('chosen')
    arguments = [chosen.properties['random-seed'], chosen.get_str('osenvironment'),
                 tree.get_str('model'), tree.get_str('compatible'), True]
    if build_nabu_tree(*arguments).serialize() != data:
        raise ValueError('Generator does not reproduce the original nabu ADT exactly')
    output = build_nabu_tree(*arguments, crypto_hash_method='sha2-384').serialize()
    checked = parse_adt(output)
    if checked.find_node('chosen').properties.pop('crypto-hash-method') != b'sha2-384\0':
        raise ValueError('Wrong Image4 hash algorithm')
    if checked.to_dict() != tree.to_dict() or not validate_adt_bytes(output)[0]:
        raise ValueError('Image4 ADT changed another property or failed validation')
    if destination.exists():
        if destination.read_bytes() != output:
            raise ValueError('Existing generated ADT has different bytes')
    else:
        with destination.open('xb') as stream:
            stream.write(output)
    return {'source_sha256': hashlib.sha256(data).hexdigest(),
            'output_sha256': hashlib.sha256(output).hexdigest(),
            'only_added_property': '/chosen/crypto-hash-method', 'value': 'sha2-384'}


def linux_path(path):
    path = str(path.resolve()).replace('\\', '/')
    return '/mnt/' + path[0].lower() + path[2:] if os.name == 'nt' else path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=['baseline', 'prelinked', 'missing-hash', 'double-register',
                                          'native-prelinked', 'native-missing-hash'], required=True)
    parser.add_argument('--kernel', type=Path, help='Explicit Actions-built native prelinked candidate')
    parser.add_argument('--prelink-report', type=Path, help='Emitter report for the explicit native candidate')
    parser.add_argument('--label', required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'project_audit/bringup-20261023')
    args = parser.parse_args()
    native = args.case.startswith('native-')
    if native and (not args.kernel or not args.prelink_report):
        parser.error('Native cases require --kernel and --prelink-report')
    if not native and (args.kernel or args.prelink_report):
        parser.error('Explicit candidate inputs require a native case')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', args.label):
        parser.error('Use a short filename-safe unique run label')
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    raw_report = ROOT / 'device_bringup/out' / ('qemu-nabu-' + args.label + '-result.json')
    summary = output / (args.label + '-summary.json')
    log = output / (args.label + '.log')
    if any(p.exists() for p in (raw_report, summary, log)):
        parser.error('Run label already used; preserve the previous observation')

    original_adt = ROOT / 'device_bringup/xnu_stage/review-evidence/nabu-ramdisk.adt'
    adt = original_adt
    adt_delta = None
    if args.case not in ('missing-hash', 'native-missing-hash'):
        adt = output / 'nabu-ramdisk-image4-sha384.adt'
        adt_delta = prepare_adt(original_adt, adt)
    kernel = (ROOT / 'mac_build/evidence/mac-batch-ci-39728106851/kernel-nabu-mockfs-native-apple-probe.macho'
              if args.case == 'baseline' else INPUTS / 'kernel-nabu-apfs-crypto-bridge.macho')
    if native:
        kernel = args.kernel.resolve()
    fixture = INPUTS / 'healthy-fixture'
    boot = '-v serial=3 debug=0x14e kt_fixed_zones=120 cpus=1 rd=md0'
    command = ['python3' if os.name == 'nt' else sys.executable,
               linux_path(ROOT / 'device_bringup/test_nabu_qemu.py'),
               '--kernel', linux_path(kernel), '--adt', linux_path(adt),
               '--initrd', linux_path(fixture / 'launchd.macho'),
               '--el0-contract', linux_path(fixture / 'el0-contract.json'),
               '--darwinboot', linux_path(ROOT / 'device_bringup/handoff_display_fix/DarwinBoot.efi'),
               '--qemu-virt-gic', '--post-handoff-seconds', '2', '--label', args.label]
    if args.case in ('prelinked', 'missing-hash'):
        boot += ' hackios-original-crypto=1'
        command += ['--crypto-provider', 'original-prelinked', '--prelink-report',
                    linux_path(INPUTS / 'kernel-nabu-apfs-crypto-bridge.json')]
        if args.case == 'prelinked':
            command.append('--require-apfs-registration')
    elif native:
        command += ['--crypto-provider', 'original-prelinked-native', '--prelink-report',
                    linux_path(args.prelink_report)]
        if args.case == 'native-prelinked':
            command.append('--require-apfs-registration')
    command += ['--boot-args', boot]
    if os.name == 'nt':
        command = ['wsl', '-d', 'kali-linux', '--', *command]
    with log.open('xb') as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    if not raw_report.is_file():
        raise SystemExit('Harness produced no report; inspect ' + str(log))
    report = json.loads(raw_report.read_text(encoding='utf-8'))
    globals_ = report.get('gdb_globals', {})
    texts = '\n'.join([globals_.get('panic_text', ''),
                       *(s['text'] for s in globals_.get('kernel_stack_strings', []))])
    texts += '\n' + '\n'.join(m.decode('ascii') for m in re.findall(
        rb'[ -~]{8,}', bytes.fromhex(globals_.get('kernel_stack_hex', ''))))
    if args.case in ('missing-hash', 'native-missing-hash'):
        accepted = (result.returncode != 0 and not report['passed'] and bool(globals_.get('_panicstr'))
                    and 'non-sensical crypto hash method' in texts)
    elif args.case == 'double-register':
        accepted = (result.returncode != 0 and not report['passed'] and bool(globals_.get('_panicstr'))
                    and globals_.get('_prng_ready') == 1
                    and globals_.get('_source_corecrypto14_status') == 5 and '!prng_ready' in texts)
    else:
        accepted = result.returncode == 0 and report['passed']
    data = {'case': args.case, 'label': args.label, 'expected_outcome_observed': accepted,
            'harness_passed': report['passed'], 'harness_exit_code': result.returncode,
            'raw_report': str(raw_report), 'command': command, 'adt_delta': adt_delta,
            'input_sha256': report.get('input_sha256'), 'apple_launchd_tested': False,
            'apfs_mount_tested': False, 'device_accessed': False}
    with summary.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2); stream.write('\n')
    print(json.dumps({'case': args.case, 'expected_outcome_observed': accepted,
                      'harness_passed': report['passed'], 'summary': str(summary)}, indent=2))
    return 0 if accepted else 1


if __name__ == '__main__':
    raise SystemExit(main())
