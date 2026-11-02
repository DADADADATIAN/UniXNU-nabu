"""Focused fail-closed tests for prepare_native_prelinked.py.

All inputs are synthetic and every emitter call is a local mock. No firmware,
Apple object, private CI output, QEMU process, or device is accessed.
"""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'prepare_native_prelinked.py'

MOCK_EMITTER = r'''#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def emit(native, original, roots, slide, early_security_init=None):
    mode_file = HERE / 'mock-mode.txt'
    if mode_file.is_file() and mode_file.read_text(encoding='utf-8').strip() == 'raise':
        raise RuntimeError('synthetic emitter failure')
    candidate_file = HERE.parent / 'mock-candidate.macho'
    candidate = candidate_file.read_bytes() if candidate_file.is_file() else native + b'MOCK'
    components = ['com.apple.filesystems.apfs']
    report = {
        'native_sha256': digest(native),
        'original_sha256': digest(original),
        'slide': slide,
        'components': components,
        'codeless_components': [],
        'kernel_interfaces': [],
        'original_executable_sha256': {components[0]: '1' * 64},
        'candidate_sha256': digest(candidate),
        'candidate_bytes': len(candidate),
        'images_modified': False,
        'source_inputs_modified': False,
        'instruction_relocation_complete': False,
        'abi_qualified': False,
        'loadable': False,
        'runtime_qualified': False,
        'full_emitter_field': {'preserved': True},
    }
    overlay_file = HERE.parent / 'mock-report-overlay.json'
    if overlay_file.is_file():
        report.update(json.loads(overlay_file.read_text(encoding='utf-8')))
    return candidate, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--prelinked', required=True, type=Path)
    parser.add_argument('--root', required=True, action='append')
    parser.add_argument('--slide', required=True, type=lambda value: int(value, 0))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    image, report = emit(
        args.kernel.read_bytes(), args.prelinked.read_bytes(),
        args.root, args.slide)
    if args.output.exists():
        raise SystemExit('mock refuses to overwrite')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)
    args.output.with_suffix('.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
'''


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make_macho(symbols=('_benign_symbol',)):
    """Build a small valid-enough ordinary ARM64 MH_EXECUTE with one symbol table."""
    strings = bytearray(b'\0')
    entries = []
    for name in symbols:
        encoded = name.encode('ascii')
        entries.append(struct.pack('<IBBHQ', len(strings), 0x01, 0, 0, 0))
        strings.extend(encoded + b'\0')
    commands_size = 72 + 24
    symoff = 32 + commands_size
    stroff = symoff + len(entries) * 16
    total_size = stroff + len(strings)
    header = struct.pack(
        '<IiiIIIII', 0xfeedfacf, 0x0100000c, 0, 2, 2, commands_size, 0, 0)
    segment = struct.pack(
        '<II16sQQQQiiII', 0x19, 72, b'__TEXT', 0x100000000,
        (total_size + 4095) & ~4095, 0, total_size, 7, 5, 0, 0)
    symtab = struct.pack(
        '<IIIIII', 2, 24, symoff, len(entries), stroff, len(strings))
    image = header + segment + symtab + b''.join(entries) + bytes(strings)
    assert len(image) == total_size
    return image


def link_report(base, **updates):
    report = {
        'returncode': 0,
        'finalization_passed': True,
        'crypto_bootstrap': 'prelinked',
        'source_bootstrap_absent': True,
        'undefined_symbol_count': 0,
        'kernel_sha256': sha256(base),
        'hardware_verified': False,
        'runtime_verified': False,
    }
    report.update(updates)
    return report


class NativePrelinkedTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='native-prelink-test-'))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        (self.tools / 'emit_prelink.py').write_text(MOCK_EMITTER, encoding='utf-8')
        (self.tools / 'native_prelink.py').write_text(
            '# mock dependency\n', encoding='utf-8')
        self.native = make_macho()
        self.original = b'original-kernel-bytes'
        self.base_path = self.root / 'base.macho'
        self.original_path = self.root / 'kernelcache.macho'
        self.base_path.write_bytes(self.native)
        self.original_path.write_bytes(self.original)
        self.link_path = self.root / 'link.json'
        self.write_link()

    def write_link(self, **updates):
        report = link_report(self.native, **updates)
        self.link_path.write_text(json.dumps(report), encoding='utf-8')

    def command(self, output, run_receipt=None):
        command = [
            sys.executable, '-B', str(SCRIPT),
            '--base', str(self.base_path),
            '--link-report', str(self.link_path),
            '--original', str(self.original_path),
            '--tools-dir', str(self.tools),
            '--output-dir', str(output),
        ]
        if run_receipt is not None:
            command.extend(['--run-receipt', str(run_receipt)])
        return command

    def run_wrapper(self, output, run_receipt=None):
        return subprocess.run(
            self.command(output, run_receipt),
            capture_output=True, text=True, encoding='utf-8')

    def assert_failed_without_output(self, output, result):
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertFalse(output.exists())

    def test_success_preserves_emitter_report_and_records_hashes(self):
        output = self.root / 'new-output'
        run = self.root / 'run.json'
        run.write_text(json.dumps({
            'databaseId': 39883202588,
            'status': 'completed',
            'conclusion': 'success',
            'headSha': 'c' * 40,
        }), encoding='utf-8')
        result = self.run_wrapper(output, run)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        candidate = output / 'kernel-nabu-ipados17-nativeci-prelinked.macho'
        report_path = output / 'kernel-nabu-ipados17-nativeci-prelinked.json'
        provenance_path = output / 'native-prelink-provenance.json'
        self.assertEqual(self.native + b'MOCK', candidate.read_bytes())
        report = json.loads(report_path.read_text(encoding='utf-8'))
        self.assertEqual({'preserved': True}, report['full_emitter_field'])
        self.assertFalse(report['abi_qualified'])
        self.assertFalse(report['loadable'])
        self.assertFalse(report['runtime_qualified'])
        provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
        self.assertEqual(sha256(candidate.read_bytes()),
                         provenance['outputs']['candidate']['sha256'])
        self.assertEqual(sha256(report_path.read_bytes()),
                         provenance['outputs']['emitter_report']['sha256'])
        self.assertEqual(sha256(self.native),
                         provenance['inputs']['base']['sha256'])
        self.assertEqual(sha256(self.original),
                         provenance['inputs']['original_decoded_kernel']['sha256'])
        self.assertEqual(sha256((self.tools / 'emit_prelink.py').read_bytes()),
                         provenance['inputs']['tools']['files']['emit_prelink.py']['sha256'])
        self.assertFalse(provenance['evidence_boundary']['qemu_verified'])
        self.assertFalse(provenance['evidence_boundary']['hardware_verified'])
        self.assertFalse(provenance['evidence_boundary']['runtime_qualified'])
        self.assertEqual([], provenance['outputs']['candidate']['macho']['forbidden_symbols'])

    def test_existing_output_is_never_overwritten(self):
        output = self.root / 'existing'
        output.mkdir()
        sentinel = output / 'keep.txt'
        sentinel.write_text('keep me', encoding='utf-8')
        result = self.run_wrapper(output)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual('keep me', sentinel.read_text(encoding='utf-8'))
        self.assertEqual(['keep.txt'], [path.name for path in output.iterdir()])

    def test_link_receipt_mismatches_fail_closed(self):
        cases = {
            'returncode': {'returncode': 1},
            'finalization': {'finalization_passed': False},
            'bootstrap-mode': {'crypto_bootstrap': 'source'},
            'source-absent': {'source_bootstrap_absent': False},
            'undefined': {'undefined_symbol_count': 1},
            'undefined-bool': {'undefined_symbol_count': False},
            'kernel-sha': {'kernel_sha256': '0' * 64},
        }
        for name, updates in cases.items():
            with self.subTest(case=name):
                self.write_link(**updates)
                output = self.root / f'link-{name}'
                result = self.run_wrapper(output)
                self.assert_failed_without_output(output, result)

    def test_native_source_provider_symbol_fails_before_emission(self):
        self.native = make_macho(('source_corecrypto14_bootstrap',))
        self.base_path.write_bytes(self.native)
        self.write_link()
        output = self.root / 'native-forbidden'
        result = self.run_wrapper(output)
        self.assert_failed_without_output(output, result)
        self.assertIn('source CoreCrypto', result.stderr)

    def test_empty_symbol_table_fails_closed(self):
        self.native = make_macho(())
        self.base_path.write_bytes(self.native)
        self.write_link()
        output = self.root / 'empty-symbol-table'
        result = self.run_wrapper(output)
        self.assert_failed_without_output(output, result)
        self.assertIn('empty symbol table', result.stderr)

    def test_candidate_source_provider_symbol_fails_closed(self):
        (self.root / 'mock-candidate.macho').write_bytes(
            make_macho(('_source_corecrypto14_status',)))
        output = self.root / 'candidate-forbidden'
        result = self.run_wrapper(output)
        self.assert_failed_without_output(output, result)
        self.assertIn('candidate symbol table', result.stderr)

    def test_emitter_report_evidence_and_flag_mismatches_fail_closed(self):
        cases = {
            'native-sha': {'native_sha256': '2' * 64},
            'original-sha': {'original_sha256': '3' * 64},
            'candidate-sha': {'candidate_sha256': '4' * 64},
            'slide': {'slide': 0},
            'flags-abi': {'abi_qualified': True},
            'flags-loadable': {'loadable': True},
            'flags-runtime': {'runtime_qualified': True},
            'flags-abi-zero': {'abi_qualified': 0},
            'source-modified': {'source_inputs_modified': True},
            'images-modified': {'images_modified': True},
            'text-coverage': {'original_executable_sha256': {}},
        }
        overlay = self.root / 'mock-report-overlay.json'
        for name, updates in cases.items():
            with self.subTest(case=name):
                overlay.write_text(json.dumps(updates), encoding='utf-8')
                output = self.root / f'report-{name}'
                result = self.run_wrapper(output)
                self.assert_failed_without_output(output, result)

    def test_emitter_failure_creates_no_output(self):
        (self.tools / 'mock-mode.txt').write_text('raise', encoding='utf-8')
        output = self.root / 'emitter-failure'
        result = self.run_wrapper(output)
        self.assert_failed_without_output(output, result)
        self.assertIn('pinned emitter failed', result.stderr)

    def test_failed_run_receipt_is_rejected(self):
        run = self.root / 'failed-run.json'
        run.write_text(json.dumps({
            'status': 'completed',
            'conclusion': 'failure',
        }), encoding='utf-8')
        output = self.root / 'failed-run-output'
        result = self.run_wrapper(output, run)
        self.assert_failed_without_output(output, result)


if __name__ == '__main__':
    unittest.main()
