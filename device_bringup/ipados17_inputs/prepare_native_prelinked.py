#!/usr/bin/env python3
"""Emit the fixed 21H16 APFS native-prelink candidate from verified CI inputs.

This wrapper is a static prelink step only. It binds the native base to a
successful CI link receipt, checks the native symbol table, runs the pinned
NativePrelink emitter, and validates its candidate and report before creating
the requested new output directory. It does not probe original component
bytes, boot QEMU, touch a device, or turn static emission into runtime
qualification.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


APFS_ROOT = 'com.apple.filesystems.apfs'
SLIDE = -20316160
CANDIDATE_NAME = 'kernel-nabu-ipados17-nativeci-prelinked.macho'
REPORT_NAME = 'kernel-nabu-ipados17-nativeci-prelinked.json'
PROVENANCE_NAME = 'native-prelink-provenance.json'
FORBIDDEN_SYMBOLS = (
    b'source_corecrypto14_bootstrap',
    b'source_corecrypto14_status',
)
TOOL_NAMES = ('native_prelink.py', 'emit_prelink.py')


class PrelinkError(Exception):
    """A fail-closed input, evidence, emitter, or output error."""


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _digest(value, label):
    if not isinstance(value, str) or len(value) != 64 or any(
            character not in '0123456789abcdefABCDEF' for character in value):
        raise PrelinkError(f'{label} must be a SHA-256 hex digest')
    return value.lower()


def _read_json(path, label):
    if not path.is_file():
        raise PrelinkError(f'{label} is not a regular file: {path}')
    data = path.read_bytes()
    try:
        value = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrelinkError(f'{label} is not UTF-8 JSON: {error}') from error
    if not isinstance(value, dict):
        raise PrelinkError(f'{label} must contain a JSON object')
    return value, data


def _parse_macho(data, label):
    """Validate ordinary ARM64 MH_EXECUTE shape and scan the real symbol table."""
    if len(data) < 32:
        raise PrelinkError(f'{label} is too short for a 64-bit Mach-O header')
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, _, _ = struct.unpack_from(
        '<IiiIIIII', data, 0)
    if (magic, cpu, subtype) != (0xfeedfacf, 0x0100000c, 0):
        raise PrelinkError(f'{label} is not an ordinary little-endian ARM64 Mach-O')
    if filetype != 2:
        raise PrelinkError(f'{label} is not MH_EXECUTE')
    if ncmds == 0 or ncmds > 65535 or sizeofcmds < 24:
        raise PrelinkError(f'{label} has invalid load-command counts')
    commands_end = 32 + sizeofcmds
    if commands_end > len(data):
        raise PrelinkError(f'{label} load commands exceed the file')

    offset = 32
    segment_count = 0
    has_text_segment = False
    symbol_table = None
    for _ in range(ncmds):
        if offset + 8 > commands_end:
            raise PrelinkError(f'{label} has a truncated load command')
        command, command_size = struct.unpack_from('<II', data, offset)
        if command_size < 8 or command_size % 8 or offset + command_size > commands_end:
            raise PrelinkError(f'{label} has an invalid load-command extent')
        if command == 0x19:
            if command_size < 72:
                raise PrelinkError(f'{label} has a truncated segment command')
            name = data[offset + 8:offset + 24].rstrip(b'\0')
            _, _, fileoff, filesize = struct.unpack_from('<4Q', data, offset + 24)
            section_count, = struct.unpack_from('<I', data, offset + 64)
            if command_size != 72 + 80 * section_count:
                raise PrelinkError(f'{label} has an inconsistent segment command')
            if fileoff > len(data) or filesize > len(data) - fileoff:
                raise PrelinkError(f'{label} segment exceeds the file')
            segment_count += 1
            has_text_segment = has_text_segment or name == b'__TEXT'
        elif command == 2:
            if command_size != 24 or symbol_table is not None:
                raise PrelinkError(f'{label} must contain exactly one LC_SYMTAB')
            symbol_table = struct.unpack_from('<4I', data, offset + 8)
        offset += command_size
    if offset != commands_end:
        raise PrelinkError(f'{label} load-command size does not match its header')
    if segment_count == 0 or not has_text_segment:
        raise PrelinkError(f'{label} lacks an ordinary __TEXT segment')
    if symbol_table is None:
        raise PrelinkError(f'{label} lacks LC_SYMTAB')

    symoff, symbol_count, stroff, string_size = symbol_table
    if symbol_count == 0:
        raise PrelinkError(
            f'{label} has an empty symbol table; absence cannot be established')
    if symoff + symbol_count * 16 > len(data):
        raise PrelinkError(f'{label} symbol table exceeds the file')
    if stroff > len(data) or string_size > len(data) - stroff:
        raise PrelinkError(f'{label} string table exceeds the file')
    strings = data[stroff:stroff + string_size]
    forbidden = set()
    for index in range(symbol_count):
        string_index, = struct.unpack_from('<I', data, symoff + index * 16)
        if string_index >= string_size:
            raise PrelinkError(f'{label} symbol {index} has an invalid string index')
        end = strings.find(b'\0', string_index)
        if end < 0:
            raise PrelinkError(f'{label} symbol {index} has an unterminated name')
        name = strings[string_index:end]
        for bare_name in FORBIDDEN_SYMBOLS:
            if name in (bare_name, b'_' + bare_name):
                forbidden.add(name.decode('ascii', errors='replace'))

    return {
        'cpu': 'arm64',
        'filetype': 'MH_EXECUTE',
        'load_command_count': ncmds,
        'segment_count': segment_count,
        'symbol_count': symbol_count,
        'forbidden_symbols': sorted(forbidden),
    }


def _validate_link_receipt(report, base_sha256):
    if report.get('returncode') != 0 or isinstance(report.get('returncode'), bool):
        raise PrelinkError('link receipt does not report returncode 0')
    if report.get('finalization_passed') is not True:
        raise PrelinkError('link receipt does not report finalization_passed=true')
    if report.get('crypto_bootstrap') != 'prelinked':
        raise PrelinkError('link receipt crypto_bootstrap is not prelinked')
    if report.get('source_bootstrap_absent') is not True:
        raise PrelinkError('link receipt does not confirm source_bootstrap_absent=true')
    undefined = report.get('undefined_symbol_count')
    if isinstance(undefined, bool) or undefined != 0:
        raise PrelinkError('link receipt undefined_symbol_count is not integer zero')
    receipt_sha256 = _digest(report.get('kernel_sha256'), 'link receipt kernel_sha256')
    if receipt_sha256 != base_sha256:
        raise PrelinkError('link receipt kernel_sha256 does not match the native base')
    return {
        'returncode': 0,
        'finalization_passed': True,
        'crypto_bootstrap': 'prelinked',
        'source_bootstrap_absent': True,
        'undefined_symbol_count': 0,
        'kernel_sha256': receipt_sha256,
    }


def _validate_run_receipt(report):
    if report.get('status') != 'completed' or report.get('conclusion') != 'success':
        raise PrelinkError('optional Actions run receipt is not a completed success')


def _tool_manifest(tools_dir):
    if not tools_dir.is_dir():
        raise PrelinkError(f'NativePrelink tools directory is missing: {tools_dir}')
    files = {}
    for name in TOOL_NAMES:
        path = tools_dir / name
        if not path.is_file():
            raise PrelinkError(f'required pinned tool is missing: {path}')
        files[name] = {
            'path': str(path),
            'bytes': path.stat().st_size,
            'sha256': _sha256_file(path),
        }
    return {'directory': str(tools_dir), 'files': files}


def _run_emitter(base_path, original_path, tools_dir, output_parent):
    emitter = tools_dir / 'emit_prelink.py'
    candidate_name = CANDIDATE_NAME
    with tempfile.TemporaryDirectory(prefix='.native-prelink-', dir=str(output_parent)) as temporary:
        temporary = Path(temporary)
        staged_candidate = temporary / candidate_name
        command = [
            sys.executable,
            '-B',
            str(emitter),
            '--kernel', str(base_path),
            '--prelinked', str(original_path),
            '--root', APFS_ROOT,
            '--slide', str(SLIDE),
            '--output', str(staged_candidate),
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise PrelinkError(
                f'pinned emitter failed with exit code {result.returncode}'
                + (f': {detail[-4000:]}' if detail else ''))
        staged_report = staged_candidate.with_suffix('.json')
        if not staged_candidate.is_file() or not staged_report.is_file():
            raise PrelinkError('pinned emitter did not produce both candidate and report')
        return (staged_candidate.read_bytes(), staged_report.read_bytes(),
                command, result.stdout)


def _validate_emitter_report(report, base_sha256, original_sha256,
                             candidate_sha256, candidate_size):
    if _digest(report.get('native_sha256'), 'emitter native_sha256') != base_sha256:
        raise PrelinkError('emitter report native_sha256 does not match the native base')
    if _digest(report.get('original_sha256'), 'emitter original_sha256') != original_sha256:
        raise PrelinkError('emitter report original_sha256 does not match the original kernel')
    slide = report.get('slide')
    if isinstance(slide, bool) or slide != SLIDE:
        raise PrelinkError('emitter report slide differs from the fixed APFS slide')
    if _digest(report.get('candidate_sha256'),
               'emitter candidate_sha256') != candidate_sha256:
        raise PrelinkError('emitter report candidate_sha256 does not match the candidate')
    candidate_bytes = report.get('candidate_bytes')
    if isinstance(candidate_bytes, bool) or candidate_bytes != candidate_size:
        raise PrelinkError('emitter report candidate_bytes does not match the candidate')

    components = report.get('components')
    if (not isinstance(components, list) or not components
            or any(not isinstance(item, str) or not item for item in components)
            or len(set(components)) != len(components)):
        raise PrelinkError('emitter report components must be a unique non-empty string list')
    if APFS_ROOT not in components:
        raise PrelinkError('emitter report does not include the fixed APFS root')

    text_hashes = report.get('original_executable_sha256')
    if not isinstance(text_hashes, dict) or set(text_hashes) != set(components):
        raise PrelinkError(
            'emitter original_executable_sha256 must cover every emitted component')
    for component, digest in text_hashes.items():
        _digest(digest, f'emitter original_executable_sha256[{component}]')

    for key in ('kernel_interfaces', 'codeless_components'):
        value = report.get(key)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise PrelinkError(f'emitter report {key} must be a string list')

    for flag in ('abi_qualified', 'loadable', 'runtime_qualified'):
        if report.get(flag) is not False:
            raise PrelinkError(f'emitter report {flag} is not exactly false')
    if report.get('source_inputs_modified') is not False:
        raise PrelinkError('emitter report source_inputs_modified is not exactly false')
    if report.get('images_modified') is not False:
        raise PrelinkError('emitter report images_modified is not exactly false')

    return {
        'components': len(components),
        'kernel_interfaces': len(report.get('kernel_interfaces') or []),
        'codeless_components': len(report.get('codeless_components') or []),
        'original_executable_sha256_entries': len(text_hashes),
        'abi_qualified': False,
        'loadable': False,
        'runtime_qualified': False,
        'source_inputs_modified': False,
        'images_modified': False,
    }


def _write_exclusive(path, data):
    with path.open('xb') as stream:
        stream.write(data)


def prepare(base, link_report, original, tools_dir, output_dir, run_receipt=None):
    base = Path(base).expanduser().resolve()
    link_report = Path(link_report).expanduser().resolve()
    original = Path(original).expanduser().resolve()
    tools_dir = Path(tools_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    run_receipt = Path(run_receipt).expanduser().resolve() if run_receipt else None

    if output_dir.exists() or output_dir.is_symlink():
        raise PrelinkError(f'refusing to reuse an existing output path: {output_dir}')
    if not output_dir.parent.is_dir():
        raise PrelinkError(f'output parent directory is missing: {output_dir.parent}')
    if not base.is_file():
        raise PrelinkError(f'native base is not a regular file: {base}')
    if not original.is_file():
        raise PrelinkError(f'original decoded kernel is not a regular file: {original}')

    base_data = base.read_bytes()
    base_size = len(base_data)
    base_sha256 = _sha256_bytes(base_data)
    native_summary = _parse_macho(base_data, 'native base')
    if native_summary['forbidden_symbols']:
        raise PrelinkError(
            'native base symbol table still contains a source CoreCrypto provider symbol')
    del base_data

    link_data, link_bytes = _read_json(link_report, 'link receipt')
    validated_link = _validate_link_receipt(link_data, base_sha256)
    original_sha256 = _sha256_file(original)
    original_bytes = original.stat().st_size
    tools = _tool_manifest(tools_dir)

    run_data = None
    run_bytes = None
    if run_receipt is not None:
        run_data, run_bytes = _read_json(run_receipt, 'Actions run receipt')
        _validate_run_receipt(run_data)

    candidate_bytes, report_bytes, emitter_command, emitter_stdout = _run_emitter(
        base, original, tools_dir, output_dir.parent)
    candidate_sha256 = _sha256_bytes(candidate_bytes)
    report_sha256 = _sha256_bytes(report_bytes)
    candidate_summary = _parse_macho(candidate_bytes, 'candidate')
    if candidate_summary['forbidden_symbols']:
        raise PrelinkError(
            'candidate symbol table still contains a source CoreCrypto provider symbol')
    try:
        emitter_report = json.loads(report_bytes.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrelinkError(f'emitter report is not UTF-8 JSON: {error}') from error
    if not isinstance(emitter_report, dict):
        raise PrelinkError('emitter report must contain a JSON object')
    validated_report = _validate_emitter_report(
        emitter_report, base_sha256, original_sha256,
        candidate_sha256, len(candidate_bytes))

    candidate_path = output_dir / CANDIDATE_NAME
    report_path = output_dir / REPORT_NAME
    provenance_path = output_dir / PROVENANCE_NAME
    provenance = {
        'schema': 'hackios-native-prelink-provenance-v1',
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'candidate_emitted',
        'parameters': {
            'root': APFS_ROOT,
            'slide': SLIDE,
            'emitter_command': emitter_command,
            'emitter_stdout': emitter_stdout.strip(),
        },
        'inputs': {
            'base': {
                'path': str(base),
                'bytes': base_size,
                'sha256': base_sha256,
                'macho': native_summary,
            },
            'original_decoded_kernel': {
                'path': str(original),
                'bytes': original_bytes,
                'sha256': original_sha256,
                'component_bytes_probed': False,
            },
            'link_report': {
                'path': str(link_report),
                'bytes': len(link_bytes),
                'sha256': _sha256_bytes(link_bytes),
                'validated_fields': validated_link,
                'receipt': link_data,
            },
            'run_receipt': ({
                'path': str(run_receipt),
                'bytes': len(run_bytes),
                'sha256': _sha256_bytes(run_bytes),
                'receipt': run_data,
            } if run_receipt is not None else None),
            'tools': tools,
        },
        'outputs': {
            'candidate': {
                'path': str(candidate_path),
                'bytes': len(candidate_bytes),
                'sha256': candidate_sha256,
                'macho': candidate_summary,
            },
            'emitter_report': {
                'path': str(report_path),
                'bytes': len(report_bytes),
                'sha256': report_sha256,
                'validated_fields': validated_report,
            },
            'provenance': {
                'path': str(provenance_path),
            },
        },
        'evidence_boundary': {
            'candidate_emitted': True,
            'ci_link_receipt_accepted': True,
            'emitter_report_preserved': True,
            'abi_qualified': False,
            'loadable': False,
            'runtime_qualified': False,
            'qemu_verified': False,
            'hardware_verified': False,
            'statement': (
                'Static prelink emission only; no boot, QEMU, ABI, or device '
                'qualification is implied.'
            ),
        },
    }
    provenance_bytes = (json.dumps(
        provenance, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')

    output_dir.mkdir(parents=False, exist_ok=False)
    _write_exclusive(candidate_path, candidate_bytes)
    _write_exclusive(report_path, report_bytes)
    _write_exclusive(provenance_path, provenance_bytes)
    return provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path,
                        help='verified native ARM64 MH_EXECUTE base')
    parser.add_argument('--link-report', required=True, type=Path,
                        help='CI link.json bound to the base SHA-256')
    parser.add_argument('--original', required=True, type=Path,
                        help='original 21H16 decoded kernelcache.macho')
    parser.add_argument('--tools-dir', required=True, type=Path,
                        help='pinned NativePrelink directory containing both tools')
    parser.add_argument('--output-dir', required=True, type=Path,
                        help='new directory to create; existing paths are refused')
    parser.add_argument('--run-receipt', type=Path,
                        help='optional completed-success Actions run.json')
    args = parser.parse_args(argv)
    try:
        provenance = prepare(
            args.base, args.link_report, args.original, args.tools_dir,
            args.output_dir, args.run_receipt)
    except PrelinkError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    outputs = provenance['outputs']
    print(json.dumps({
        'candidate': outputs['candidate']['path'],
        'candidate_sha256': outputs['candidate']['sha256'],
        'emitter_report': outputs['emitter_report']['path'],
        'emitter_report_sha256': outputs['emitter_report']['sha256'],
        'provenance': outputs['provenance']['path'],
        'abi_qualified': False,
        'loadable': False,
        'runtime_qualified': False,
    }, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
