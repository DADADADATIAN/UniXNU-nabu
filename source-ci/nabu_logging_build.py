"""Attach an explicitly requested log recorder without changing other profiles."""
import hashlib
from pathlib import Path
import shutil
import json
import struct
import subprocess


def enable_logging(upstream, device):
    build = upstream / 'scripts/build-xnu-4k-baseline.sh'
    text = build.read_text(encoding='utf-8')
    anchor = 'python3 scripts/prepare-xnu-source.py\n'
    if text.count(anchor) != 1:
        raise ValueError('Expected the pinned XNU source preparation call')
    text = text.replace(anchor, anchor +
        'if [ "${NABU_CAPTURE_LOG:-0}" = 1 ]; then\n'
        '  python3 scripts/nabu_capture_source.py --root "$ROOT" --device "$UNIXNU_DEVICE"\n'
        'fi\n', 1)
    anchor = 'for LATE_PATCH in '
    if text.count(anchor) != 1:
        raise ValueError('Expected the pinned late-patch reversal loop')
    text = text.replace(anchor,
        'if [ "${NABU_CAPTURE_LOG:-0}" = 1 ]; then\n'
        '  python3 scripts/nabu_capture_source.py --root "$ROOT" --restore-data-progress\n'
        'fi\n' + anchor, 1)
    build.write_text(text, encoding='utf-8')
    shutil.copyfile(device / 'scripts/nabu_capture_source.py', upstream / 'scripts/nabu_capture_source.py')
    kernel = upstream / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    # Set the flag before BOTH the bootstrap compilation and archive production.
    # The upstream build receives `env` through run(..., env=env).
    anchor = '    build_archives(ctx, env)\n'
    if text.count(anchor) != 1:
        raise ValueError('Expected the pinned archive build call')
    # Find the first baseline build call's environment construction below.
    marker = '    env = dict(os.environ)\n'
    if text.count(marker) != 1:
        raise ValueError('Expected exactly one kernel build environment')
    text = text.replace(marker, marker + "    env['NABU_CAPTURE_LOG'] = '1'\n", 1)
    kernel.write_text(text, encoding='utf-8')
    identity = hashlib.sha256()
    for p in sorted((device / 'ufs').glob('NabuLog*.h')):
        identity.update(p.name.encode() + b'\0' + p.read_bytes())
    identity.update(b'nabu_capture_source.py\0' + (device / 'scripts/nabu_capture_source.py').read_bytes())
    identity.update(b'NabuHeartbeat.cpp\0' + (device / 'platform/NabuHeartbeat.cpp').read_bytes())
    return {'format': 'NABULOG2', 'recorder': True, 'persistence_default': 'off',
            'write_gate': 'nabu-log=1 + allocation token + runtime GPT/FAT ownership proof',
            'source_identity': identity.hexdigest(), 'runtime_qualified': False}


def qualify_logging_candidate(upstream, candidate, expected_source_identity=None):
    """Bind real hook objects, their UFS calls and final definitions to this build."""
    tree = upstream / 'out/nabu/tree'
    report = json.loads((tree / 'build/native-ufs/build-report.json').read_text())
    if report.get('log_capture') is not True or report.get('log_persistence_default') != 'off':
        raise ValueError('UFS archive does not declare the gated log writer')
    if expected_source_identity and report.get('logging_source_identity') != expected_source_identity:
        raise ValueError('Logging archive source identity does not match preparation')
    data = candidate.read_bytes()
    at, symbols = 32, None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if command == 2:
            symbols = struct.unpack_from('<4I', data, at + 8)
        at += size
    if symbols is None:
        raise ValueError('Logging candidate has no symbol table')
    offset, count, strings, extent = symbols
    found = {}
    required = {'_nabu_capture_append', '_nabu_capture_snapshot', '_nabu_capture_copy',
                '_nabu_console_write_captured', '_nabu_trace_user_exception', '_nabu_trace_exit_panic',
                '_nabu_boot_watch_poll', '_nabu_data_mount_progress',
                '_nabu_log_writer_state', '_nabu_log_writer_rounds', '_nabu_log_writer_failures'}
    for i in range(count):
        name, kind, _, _, address = struct.unpack_from('<IBBHQ', data, offset + 16 * i)
        if kind & 0xe0 or kind & 0xe != 0xe or name >= extent:
            continue
        end = data.index(b'\0', strings + name, strings + extent)
        name = data[strings + name:end].decode()
        if name in required:
            found[name] = hex(address)
    if set(found) != required:
        raise ValueError('Missing real log definitions: ' + str(sorted(required - set(found))))
    objdump = next((p for p in ('/opt/homebrew/opt/llvm/bin/llvm-objdump',
                               '/usr/local/opt/llvm/bin/llvm-objdump') if Path(p).is_file()),
                   shutil.which('llvm-objdump'))
    if not objdump:
        raise ValueError('LLVM object relocation reader is required for log qualification')
    obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    paths = {'console': obj / 'osfmk/DEVELOPMENT/serial_console.o',
             'printbuf': obj / 'osfmk/DEVELOPMENT/serial_general.o',
             'kprintf': obj / 'pexpert/DEVELOPMENT/pe_kprintf.o',
             'ufs': tree / 'build/native-ufs/NativeUfs.o'}
    source_report = json.loads((tree / 'build/nabu-log/source-report.json').read_text())
    if source_report.get('data_mount_trace'):
        paths['data_mount'] = obj / 'bsd/DEVELOPMENT/kern_exec.o'
    paths['user_exception'] = obj / 'osfmk/DEVELOPMENT/exception.o'
    paths['exit_panic_state'] = obj / 'bsd/DEVELOPMENT/kern_exit.o'
    observations = {}
    for role, path in paths.items():
        result = subprocess.run([objdump, '-r', str(path)], capture_output=True, text=True, check=True)
        calls = [line.strip() for line in result.stdout.splitlines()
                 if 'ARM64_RELOC_BRANCH26' in line and
                 any(name in line for name in ('_nabu_capture_', '_nabu_console_write_captured',
                                               '_nabu_boot_watch_poll', '_nabu_data_mount_progress',
                                               '_nabu_trace_user_exception', '_nabu_trace_exit_panic'))]
        expected = ['_nabu_trace_exit_panic'] if role == 'exit_panic_state' else (
            ['_nabu_trace_user_exception'] if role == 'user_exception' else (
            ['_nabu_data_mount_progress'] if role == 'data_mount' else (
            ['_nabu_capture_append'] if role == 'kprintf' else (
            ['_nabu_capture_snapshot', '_nabu_capture_copy', '_nabu_boot_watch_poll'] if role == 'ufs' else (
            ['_nabu_capture_append', '_nabu_console_write_captured'] if role == 'printbuf' else [])))))
        if any(not any(name in line for line in calls) for name in expected):
            raise ValueError('Logging calls absent from actual ' + role + ' object')
        observations[role] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'calls': calls}
    source_report = json.loads((tree / 'build/nabu-log/source-report.json').read_text())
    for name, sha in source_report['hooks'].items():
        if hashlib.sha256((tree / '.cache/xnu-work' / name).read_bytes()).hexdigest() != sha:
            raise ValueError('Actual console source differs from its hook receipt')
    return {'final_definitions': found, 'objects': observations,
            'candidate_sha256': hashlib.sha256(data).hexdigest(),
            'persistence_default': 'off', 'runtime_qualified': False}
