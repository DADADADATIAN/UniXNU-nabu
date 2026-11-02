#!/usr/bin/env python3
"""Prepare a review-only nabu CPU-display file package. Never access a device.

All inputs are local and remain unchanged. The package has no installer, raw
partition image, reboot action, or claim of FAT power-loss atomicity.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import sys
import tomllib

try:
    from . import nabu_log_volume as volume
except ImportError:
    import nabu_log_volume as volume

ROOT = Path(__file__).resolve().parents[1]
for directory in ('device_bringup', 'device_bringup/xnu_stage',
                  'device_bringup/adt', 'source-ci'):
    sys.path.insert(0, str(ROOT / directory))
from prepare_hardware_test import FatImage
from compact_loader_kernel import compact
from validate_adt import parse_adt
from collect_outputs import macho_summary
from nabu_display_ci import HARDWARE_CPU_PROFILE, REFERENCE, compare_abi, symbols_and_segments
from nabu_gpu_ci import (PROFILE as GPU_PROFILE, CONTRACT as GPU_CONTRACT,
                         GPU_PROFILES, accelerator_mode, gpu_contract,
                         public_source, qualify_gpu_bundle, source_scripts)
from prepare_source import INPUT_SHA256, UPSTREAM

PROFILE = HARDWARE_CPU_PROFILE
ENTRY = 'nabu-console-log-v2'
MENU = '/EFI/UniXNU/unixnu.toml'
DISPLAY = 'outputs/tree/build/native-legacy-display/'
UFS = 'outputs/tree/build/native-ufs/'
ROOT_ARGUMENTS = ('native-ufs-os-lba', 'native-ufs-os-sectors',
                  'native-ufs-systemos-lba', 'native-ufs-systemos-sectors')
QEMU_FLAGS = ('qemu_data', 'qemu_cpu_ui_reference', 'qemu_legacy_discovery', 'qemu_cpu_present')
LOG_SYMBOLS = {'_nabu_capture_append', '_nabu_capture_copy', '_nabu_capture_snapshot',
               '_nabu_console_write_captured', '_nabu_log_writer_state',
               '_nabu_log_writer_rounds', '_nabu_log_writer_failures'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    result = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
    require(isinstance(result, dict), 'Expected a JSON object: ' + str(path))
    return result


def no_links(path):
    for current in (path, *path.parents):
        require(not current.is_symlink() and not getattr(current, 'is_junction', lambda: False)(),
                'Linked input/output path is not supported: ' + str(path))


def relative_file(root, name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name,
            'Manifest path is not a normal relative path')
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and relative.as_posix() == name and
            all(part not in ('.', '..') for part in relative.parts), 'Manifest path traversal')
    path = root.joinpath(*relative.parts)
    no_links(path)
    require(path.resolve().is_relative_to(root.resolve()) and path.is_file(),
            'Missing or escaped manifest member: ' + name)
    return path


def validate_ci(ci_dir, expected):
    profile = expected.get('profile', PROFILE)
    require(profile in (PROFILE, *GPU_PROFILES), 'Unsupported hardware package profile')
    gpu_enabled = profile in GPU_PROFILES
    ci_dir = ci_dir.resolve()
    manifest_path = relative_file(ci_dir, 'source-manifest.json')
    require(file_sha(manifest_path) == expected['manifest_sha256'], 'Source manifest SHA mismatch')
    manifest = read_json(manifest_path)
    summary = manifest.get('summary', {})
    require(isinstance(summary, dict), 'Missing CI summary object')
    identity = {key: expected[key] for key in ('run_id', 'run_attempt', 'head_sha', 'inputs_sha256')}
    expected_gpu = gpu_contract(profile) if gpu_enabled else None
    for document in (manifest, summary):
        require(all(document.get(key) == value for key, value in identity.items()), 'CI identity mismatch')
        require(document.get('profile') == profile and
                document.get('ufs_cpu_present') is (not gpu_enabled) and
                (document.get('ufs_gpu') is True if gpu_enabled else document.get('ufs_gpu', False) is False) and
                all(document.get(key) is False for key in QEMU_FLAGS), 'Not the explicit hardware CPU/GPU profile')
        require(document.get('gpu') == expected_gpu if gpu_enabled else not document.get('gpu'),
                'Hardware package has a mismatched GPU contract')
        require(document.get('upstream_commit') == UPSTREAM and document.get('input_verified') is True and
                document.get('inputs_release') == 'unixnu-source-inputs' and
                document.get('inputs_asset') == 'ipsw-21h16-small.zip' and
                document.get('build_step_outcome') == 'success', 'Unqualified CI input/build identity')
        require(document.get('runtime_qualified') is False, 'CI evidence must not claim runtime qualification')
    require(expected['inputs_sha256'] == INPUT_SHA256 and manifest.get('actual_upstream_commit') == UPSTREAM,
            'Wrong pinned 21H16 input or upstream')
    require(all(summary.get(key) is True for key in ('candidate_present', 'candidate_validated',
                'data_skeleton_qualified_statically', 'logging_qualified_statically',
                'display_qualified_statically')), 'Missing candidate/Data/logging/display qualification')
    require(summary.get('undefined_symbol_count') == 0, 'CI reports undefined symbols')
    require(summary.get('gpu_qualified_statically') is True if gpu_enabled else
            not summary.get('gpu_qualified_statically') and not manifest.get('gpu_qualification'),
            'Missing or unexpected GPU static qualification')
    files = manifest.get('files', {})
    require(isinstance(files, dict) and 0 < len(files) <= 4096, 'Invalid source manifest member list')
    seen = set()
    for name, metadata in files.items():
        require(name.casefold() not in seen, 'Case-aliased manifest paths')
        seen.add(name.casefold())
        path = relative_file(ci_dir, name)
        require(type(metadata.get('bytes')) is int and metadata['bytes'] == path.stat().st_size and
                file_sha(path) == metadata.get('sha256'), 'Manifest member hash/size mismatch: ' + name)

    def member(name):
        require(name in files, 'Required evidence is not manifest-bound: ' + name)
        return relative_file(ci_dir, name)

    raw_path, raw_report_path = member('outputs/kernel/kernel.macho'), member('outputs/kernel/kernel.json')
    raw_hash = files['outputs/kernel/kernel.macho']['sha256']
    require(raw_path.stat().st_size <= 256 * 1024 * 1024, 'Raw kernel exceeds the bounded host input budget')
    prelink = read_json(raw_report_path)
    require('loader_container' not in prelink, 'CI candidate must be the raw prelink output')
    require(summary.get('candidate_sha256') == raw_hash == prelink.get('candidate_sha256') and
            summary.get('candidate_bytes') == raw_path.stat().st_size and prelink.get('slide') == -0x1360000,
            'Raw candidate/sidecar identity mismatch')
    actual_macho = macho_summary(raw_path)
    require(actual_macho == manifest.get('macho') and not actual_macho['undefined_names'] and
            actual_macho['symbol_count'] > 0, 'Actual candidate has an invalid symbol table')
    required_images = {'com.apple.filesystems.apfs', 'com.apple.kec.corecrypto',
                       'com.apple.driver.AppleMobileFileIntegrity', 'com.apple.security.sandbox',
                       'com.apple.iokit.IOSurface', 'com.apple.iokit.IOMobileGraphicsFamily'}
    if accelerator_mode(profile):
        # The published accelerator subclasses the original IOAcceleratorES, so a
        # metal package must carry the kext that defines it. The diagnostic GPU
        # profile publishes nothing and keeps its closure free of IOGPUFamily.
        required_images.add('com.apple.iokit.IOGPUFamily')
    require(required_images <= set(prelink.get('components', [])), 'Missing original system/graphics closure')
    board = tomllib.loads(member('device/board.toml').read_text())
    require(board.get('kernel', {}).get('defconfig') == profile and board.get('board', {}).get('name') == 'nabu'
            and board.get('board', {}).get('soc') == 'SM8150' and board.get('ipsw', {}).get('build') == '21H16',
            'Manifest-bound board is not the selected nabu/21H16 hardware profile')
    config = member('outputs/.config').read_text().splitlines()
    assignments = [line.split('=', 1)[0] for line in config if line.startswith('CONFIG_')]
    require(len(assignments) == len(set(assignments)), 'Duplicate build configuration')
    require(all('CONFIG_XNU_' + key + '=y' in config for key in (
        'NATIVE_UFS', 'NATIVE_RAM_BLOCK', 'OWNER_DATA_MOUNT', 'OWNER_ROOT_TRUST',
        'OWNER_UNION_SYSTEMOS', 'NATIVE_LEGACY_DISPLAY')), 'Missing hardware/Data/display build dependency')
    require(all('CONFIG_XNU_' + key + '=n' in config for key in
                ('BOOT_PROGRESS', 'NATIVE_MOBILE_DISPLAY')) and
            'CONFIG_XNU_NATIVE_ADRENO=' + ('y' if gpu_enabled else 'n') in config,
            'Unexpected Adreno or display build dependency')
    require(read_json(member('outputs/tree/build/armdt-platform/build-report.json')).get('boot_pmgr') ==
            'NabuBootPMGR', 'Hardware candidate uses the wrong PMGR backend')
    prepared = read_json(member('prepare-report.json'))
    data = manifest.get('data_skeleton_qualification', {})
    require(isinstance(data, dict) and data and prepared.get('data_skeleton') and data.get('runtime_qualified') is False and
            data.get('capture_stage5_observer') is True and
            data.get('directory_count', 0) > 0 and data.get('patch_sha256') ==
            prepared['data_skeleton'].get('after_sha256'), 'Data skeleton proof mismatch')
    require(file_sha(member(data['source'])) == data.get('source_sha256'), 'Data helper source mismatch')

    logging = manifest.get('logging_qualification', {})
    require(isinstance(logging, dict), 'Missing logging qualification object')
    ufs = read_json(member(UFS + 'build-report.json'))
    capture = manifest.get('log_capture') or {}
    build_id = ufs.get('logging_source_identity', '')
    require(capture.get('format') == 'NABULOG2' and capture.get('recorder') is True and
            re.fullmatch('[0-9a-f]{64}', build_id) and capture.get('source_identity') == build_id and
            ufs.get('log_capture') is True and ufs.get('log_persistence_default') == 'off' and
            logging.get('candidate_sha256') == raw_hash and logging.get('runtime_qualified') is False,
            'Missing or mismatched NABULOG2 writer')
    require(file_sha(member(UFS + 'libNativeUfs.a')) == ufs.get('archive_sha256'), 'UFS archive mismatch')
    ufs_object = logging.get('objects', {}).get('ufs', {})
    require(file_sha(member(UFS + 'NativeUfs.o')) == ufs_object.get('sha256') and
            any('_nabu_capture_snapshot' in call for call in ufs_object.get('calls', [])) and
            any('_nabu_capture_copy' in call for call in ufs_object.get('calls', [])), 'Writer object lacks capture binding')
    definitions = logging.get('final_definitions', {})
    symbols, _ = symbols_and_segments(raw_path.read_bytes())
    require(LOG_SYMBOLS <= set(definitions) and all(symbols.get(name) == int(address, 16)
            for name, address in definitions.items()), 'Writer final definitions mismatch')

    display = manifest.get('display_qualification', {})
    require(isinstance(display, dict), 'Missing display qualification object')
    built = read_json(member(DISPLAY + 'build-report.json'))
    scope = {'profile': profile, 'data_backend': 'volatile_ram', 'system_transport': 'ufs', 'boot_pmgr': 'nabu'}
    require(display.get('profile') == profile and built.get('profile') == profile and
            display.get('mode') == 'cpu_present' and built.get('cpu_present') is True and
            built.get('discovery_only') is False and display.get('candidate_sha256') == raw_hash and
            display.get('vtable_slots_verified') == 358 and display.get('aliases_verified', 0) > 0 and
            display.get('pixel_transfer_enabled') is True and display.get('runtime_qualified') is False and
            display.get('pixel_transfer_runtime_observed') is False and
            display.get('user_client_interposition') is False and
            display.get('notification_profile_qualification') == scope == built.get('notification_profile_qualification') and
            display.get('reference') == REFERENCE == manifest.get('display_reference') and
            built.get('reference_candidate_sha256') == REFERENCE['candidate_sha256'], 'Display qualification mismatch')
    require(all(item.get('key_operations_supported') is False and item.get('key_state_queries_supported') is False
                and item.get('ephemeral_notification_transport_compiled') is True for item in (display, built)),
            'Notification endpoint must not supply key/state operations')
    require(file_sha(member(DISPLAY + 'libNativeLegacyDisplay.late.a')) ==
            display.get('archive_sha256') == built.get('archive_sha256'), 'Display archive mismatch')
    abi = read_json(member(DISPLAY + 'abi/display-abi.json'))
    final = read_json(member(DISPLAY + 'final-abi/display-abi.json'))
    compare_abi(abi, final)
    require(len(final.get('methods', [])) == 358 and
            all(row.get('slot') == index for index, row in enumerate(final['methods'])) and
            final.get('runtime_qualified') is False and final.get('images_modified') is False and
            final.get('contracts', {}).get('cpu_present', {}).get('status') == 'static_qualified' and
            final['contracts']['cpu_present'] == abi.get('contracts', {}).get('cpu_present') and
            all(final.get('candidate', {}).get(name, {}).get('candidate_sha256') == raw_hash
                for name in ('family', 'iosurface')), 'Final CPU ABI evidence mismatch')
    require(final.get('kernelcache_sha256') == abi.get('kernelcache_sha256') == prelink.get('original_sha256'),
            'Original kernelcache identity differs across prelink and ABI evidence')
    gpu = None
    if gpu_enabled:
        require(prepared.get('profile') == profile and prepared.get('ufs_gpu') is True and
                isinstance(prepared.get('gpu'), dict) and
                all(prepared['gpu'].get(key) == value
                    for key, value in gpu_contract(profile).items() if key != 'profile'),
                'Prepared GPU scope is not manifest-bound to the selected profile')
        names = [name.removeprefix('device/') for name in files
                 if name.startswith('device/') and public_source(name.removeprefix('device/'))]
        names.extend(source_scripts(profile))
        gpu = qualify_gpu_bundle(lambda name: member(name).read_bytes(), raw_path.read_bytes(),
                                 names, profile)
        require(gpu == manifest.get('gpu_qualification'), 'GPU qualification replay mismatch')
        ui = gpu.get('userprobe_boot', {}).get('ui_watch', {})
        require(bool(ui.get('compiled')) == prepared.get('ui_watch', False) == summary.get('ui_watch', False),
                'UI observer intent/candidate binding mismatch')
        require(not ui.get('compiled') or summary.get('ui_watch_qualified_statically') is True,
                'Requested UI observer was not qualified')
    return {'manifest': manifest, 'prelink': prelink, 'raw_path': raw_path, 'profile': profile,
            'raw_sha256': raw_hash, 'logging_build_id': build_id, 'verified_members': len(files),
            'source_manifest': str(manifest_path), 'raw_report_sha256': file_sha(raw_report_path),
            'static_qualification': {'data': data, 'display': display,
                'final_display_abi_sha256': files[DISPLAY + 'final-abi/display-abi.json']['sha256'],
                'logging': {'candidate_sha256': raw_hash, 'source_identity': build_id,
                            'final_definition_names': sorted(definitions), 'runtime_qualified': False},
                **({'gpu': gpu} if gpu_enabled else {})}}


def load_span(data):
    require(len(data) >= 32 and struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0, 2),
            'Expected an ordinary ARM64 executable')
    count, extent = struct.unpack_from('<II', data, 16)
    require(0 < count <= 65536 and extent <= len(data) - 32, 'Invalid Mach-O command bounds')
    ranges, at = [], 32
    for _ in range(count):
        require(at + 8 <= 32 + extent, 'Truncated Mach-O command')
        command, size = struct.unpack_from('<II', data, at)
        require(size >= 8 and at + size <= 32 + extent, 'Invalid Mach-O command size')
        if command == 0x19:
            require(size >= 72, 'Truncated Mach-O segment')
            address, memory, offset, backed = struct.unpack_from('<4Q', data, at + 24)
            sections = struct.unpack_from('<I', data, at + 64)[0]
            require(72 + 80 * sections <= size and backed <= memory and offset <= len(data) and
                    backed <= len(data) - offset and address + memory <= 1 << 64, 'Invalid segment extent')
            if memory:
                ranges.append((address, address + memory))
        at += size
    require(at == 32 + extent and ranges, 'Missing or malformed loadable segments')
    start, end = min(row[0] for row in ranges), max(row[1] for row in ranges)
    # Host resource bound, not a claim about the tablet's installed RAM.
    require(end - start <= 512 * 1024 * 1024, 'Compaction proof exceeds the bounded host memory budget')
    return {'virtual_start': start, 'virtual_end': end, 'memory_bytes': end - start}


def validate_compact(ci, directory):
    kernel, report_path = relative_file(directory, 'kernel.macho'), relative_file(directory, 'kernel.json')
    report = read_json(report_path)
    container = report.get('loader_container') or {}
    digest = file_sha(kernel)
    require(report.get('candidate_sha256') == digest and report.get('candidate_bytes') == kernel.stat().st_size and
            container.get('source_candidate_sha256') == ci['raw_sha256'] and
            container.get('loaded_memory_identical') is True and
            container.get('original_kernel_header_retained') is True, 'Compact report binding mismatch')
    original = ci['raw_path'].read_bytes()
    require(sha(original) == ci['raw_sha256'], 'Raw input changed during qualification')
    span = load_span(original)
    packed, segments, memory_bytes = compact(original)
    require(sha(packed) == digest and len(packed) == kernel.stat().st_size and
            container.get('segments') == segments and container.get('memory_bytes') == memory_bytes == span['memory_bytes'],
            'Actual compact bytes or loaded memory differ from the portable recomputation')
    raw_fields = {key: value for key, value in report.items()
                  if key not in ('candidate_sha256', 'candidate_bytes', 'loader_container')}
    require(raw_fields == {key: value for key, value in ci['prelink'].items()
                           if key not in ('candidate_sha256', 'candidate_bytes', 'loader_container')},
            'Compact sidecar changed prelink evidence')
    return kernel, {'sha256': digest, 'bytes': len(packed), 'segments': segments,
                    'report_sha256': file_sha(report_path),
                    'loaded_memory_identical_recomputed': True, **span}


def boot_tokens(arguments):
    require(isinstance(arguments, str) and not any(char in arguments for char in '\x00\r\n\"\''),
            'Boot arguments must be an unambiguous single-line token list')
    tokens, values = arguments.split(), {}
    for token in tokens:
        key, _, value = token.partition('=')
        require(key and key not in values, 'Duplicate boot argument: ' + key)
        values[key] = value
    return tokens, values


def hardware_menu(text, token, notifications):
    require(type(notifications) is bool, 'Notification mode must be explicit')
    before = tomllib.loads(text)
    entries = before.get('entry', [])
    ids = [entry.get('id') for entry in entries]
    require(len(ids) == len(set(ids)) and ids.count(ENTRY) == 1 and
            before.get('boot', {}).get('default') == ENTRY, 'Expected the selected current default exactly once')
    entry = entries[ids.index(ENTRY)]
    require(entry.get('type') == 'xnu' and re.fullmatch(r'Payloads/[A-Za-z0-9_.-]+\.macho', entry.get('path', '')),
            'Target kernel must be a normal existing payload path')
    tokens, old = boot_tokens(entry.get('args'))
    require(old.get('native-ufs-root') == '1' and all(key in old and int(old[key], 0) > 0 for key in ROOT_ARGUMENTS),
            'Missing explicit existing hardware root windows')
    require(old.get('nabu-log') == '1' and old.get('nabu-log-token') == token, 'Existing menu log token mismatch')
    changes = {'offline-mobile-graphics-load': '1', 'offline-legacy-register': '1',
               'offline-legacy-phase': '4', 'offline-legacy-gop': '1', 'nabu-cpu-present': '1',
               'nabu-display-status': '1', 'nabu-keybag-notifications': '1' if notifications else '0',
               'nabu-exit-trace': '1'}
    removed = ('panic_on_error_exit', 'offline-legacy-cpu-present')
    new_tokens = [item for item in tokens if item.partition('=')[0] not in (*changes, *removed)]
    new_tokens += [key + '=' + value for key, value in changes.items()]
    new_arguments = ' '.join(new_tokens)
    headers = list(re.finditer(r'(?m)^[ \t]*\[\[entry\]\][ \t]*(?:#[^\r\n]*)?\r?$', text))
    require(len(headers) == len(entries), 'Unsupported or ambiguous menu entry syntax')
    updated = None
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        block = text[header.start():end]
        if tomllib.loads(block)['entry'][0].get('id') != ENTRY:
            continue
        block, count = re.subn(r'(?m)^([ \t]*)args[ \t]*=[^\r\n]*(\r?)$',
                              lambda match: match[1] + 'args = ' + json.dumps(new_arguments) + match[2], block)
        require(count == 1, 'Selected args assignment is not a unique single line')
        updated = text[:header.start()] + block + text[end:]
    require(updated is not None, 'Selected menu entry was not located')
    expected = copy.deepcopy(before)
    expected['entry'][ids.index(ENTRY)]['args'] = new_arguments
    require(tomllib.loads(updated) == expected, 'Menu edit changed another entry or default policy')
    _, new = boot_tokens(new_arguments)
    differences = [{'key': key, 'before': old.get(key), 'after': new.get(key)}
                   for key in sorted(set(old) | set(new)) if old.get(key) != new.get(key)]
    return updated, entry, {
        'entry': ENTRY, 'before': entry['args'], 'after': new_arguments, 'changes': differences,
        'diagnostic_stop_condition_change': 'Remove panic_on_error_exit; retain exit tracing. Apple signal/exit policy is unchanged.',
        'diagnostic_panic_argument_removed': 'panic_on_error_exit' in old,
        'obsolete_argument_removed': 'offline-legacy-cpu-present' if 'offline-legacy-cpu-present' in old else None,
        'default_unchanged': True,
        'non_target_entries_unchanged': True,
        'shared_kernel_entries': [item['id'] for item in entries
                                  if str(item.get('path', '')).casefold() == entry['path'].casefold()],
    }


def payload_path(name):
    require(isinstance(name, str) and re.fullmatch(r'Payloads/[A-Za-z0-9_.-]+', name), 'Unsafe preserved payload path')
    basename = name.split('/', 1)[1].split('.', 1)[0].upper()
    require(basename not in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                             *(f'LPT{i}' for i in range(1, 10))}, 'Reserved payload device filename')
    return '/EFI/UniXNU/' + name


def space_plan(free, old_kernel_allocation, old_menu_allocation, kernel_bytes, menu_bytes, cluster_bytes):
    require(all(type(value) is int and value >= 0 for value in
                (free, old_kernel_allocation, old_menu_allocation, kernel_bytes, menu_bytes)) and
            type(cluster_bytes) is int and cluster_bytes > 0, 'Invalid space accounting input')
    rounded = lambda size: (size + cluster_bytes - 1) // cluster_bytes * cluster_bytes
    staged = rounded(kernel_bytes) + rounded(menu_bytes)
    growth = max(0, rounded(kernel_bytes) - old_kernel_allocation) + max(0, rounded(menu_bytes) - old_menu_allocation)
    return {'free_bytes': free, 'old_kernel_allocation_bytes': old_kernel_allocation,
            'old_menu_allocation_bytes': old_menu_allocation, 'parallel_staging_required_bytes': staged,
            'parallel_staging_fits': staged <= free, 'target_chain_growth_bytes': growth,
            'replacement_space_fits': growth <= free, 'atomic_replacement_proven': False,
            'automatic_deletion_allowed': False,
            'boundary': 'Payload allocation budget only; directory metadata and replacement protocol still require review.',
            'condition': ('file_level_replacement_requires_review' if staged <= free else
                          'non_atomic_replacement_requires_off_device_recovery' if growth <= free else
                          'blocked_insufficient_space_even_reusing_targets')}


def prepare_package(*, ci_dir, compact_dir, esp_path, verification_path, out, expected, notifications):
    for path in (ci_dir, compact_dir, esp_path, verification_path, out):
        no_links(path)
    require(not out.exists(), 'Output directory already exists')
    out = out.resolve()
    require(not any(out.is_relative_to(path.resolve()) for path in (ci_dir, compact_dir, esp_path.parent)),
            'Output must not be placed inside an input directory')
    require(type(expected.get('run_id')) is int and expected['run_id'] > 0 and
            type(expected.get('run_attempt')) is int and expected['run_attempt'] > 0 and
            re.fullmatch('[0-9a-f]{40}', expected.get('head_sha', '')) and
            all(re.fullmatch('[0-9a-f]{64}', expected.get(key, ''))
                for key in ('inputs_sha256', 'manifest_sha256')), 'Explicit CI identity is malformed')
    ci = validate_ci(ci_dir, expected)
    kernel, candidate = validate_compact(ci, compact_dir)
    verification = read_json(verification_path)
    recorded = Path(verification.get('image', '').replace('\\', '/'))
    recorded = recorded if recorded.is_absolute() else ROOT / recorded
    require(verification.get('status') == 'complete_rollback_verified' and recorded.resolve() == esp_path.resolve(),
            'Complete verified rollback receipt is required')
    before = FatImage(esp_path)
    require(len(before.data) == verification.get('bytes') and sha(before.data) == verification.get('sha256'),
            'Rollback image hash/size mismatch')
    fat = volume.FatVolume(lambda first, count: before.data[first * volume.BLOCK:(first + count) * volume.BLOCK],
                          len(before.data) // volume.BLOCK)
    owners = fat.ownership()
    log_start, log_count, token_bytes = fat.log_extent()
    token = token_bytes.hex()
    require(token == verification.get('log_token') and before.free_bytes == verification.get('free_bytes'),
            'Rollback allocation token/free-space proof mismatch')
    menu_before = before.read(MENU)
    menu_text, entry, arguments = hardware_menu(menu_before.decode('utf-8-sig'), token, notifications)
    menu_after = menu_text.encode('utf-8')
    target = payload_path(entry['path'])
    old_kernel = before.read(target)
    require(sha(old_kernel) == verification.get('current_kernel_sha256'), 'Current rollback kernel identity mismatch')
    old_span = load_span(old_kernel)
    preserved_paths = {payload_path(entry.get('adt', entry['path'] + '.adt')),
                       payload_path(entry.get('trustcache', entry['path'] + '.trustcache')),
                       payload_path(entry.get('initrd')),
                       '/EFI/UniXNU/UniXNU.efi', '/EFI/UniXNU/Drivers/DarwinBoot.efi'}
    preserved_paths.update(item['path'] for item in before.files.values() if not item['directory'] and
                           item['path'].lower().endswith('.efi') and '/backups/' not in item['path'].lower())
    preserved = []
    for path in sorted(preserved_paths):
        data = before.read(path)
        preserved.append({'esp_path': path, 'bytes': len(data), 'sha256': sha(data), 'package_action': 'unchanged'})
    adt_path = payload_path(entry.get('adt', entry['path'] + '.adt'))
    tree = parse_adt(before.read(adt_path))
    chosen = tree.find_node('/chosen')
    require(chosen is not None, 'Preserved hardware ADT has no chosen node')
    window = chosen.get_property('darwinboot-memory-size')
    require(window is not None and len(window) == 8, 'Preserved loader memory window is missing')
    window_bytes = struct.unpack('<Q', window)[0]
    loaded_payloads = candidate['memory_bytes'] + sum(item['bytes'] for item in preserved
                                                    if item['esp_path'] in preserved_paths and not item['esp_path'].lower().endswith('.efi'))
    require(candidate['memory_bytes'] <= window_bytes and loaded_payloads <= window_bytes,
            'Known kernel/data/ADT/trust payloads exceed the preserved loader window')
    defaults = tree.find_node('/defaults')
    require(defaults is None or defaults.get_u32('vmm-present') in (None, 0), 'Preserved ADT is a QEMU guest input')
    intc = tree.find_node('/arm-io/intc')
    timer = intc.get_property('virtual-timer-intid') if intc else None
    require(timer is not None and len(timer) == 4 and struct.unpack('<I', timer)[0] == 19,
            'Hardware ADT must retain the verified 4-byte virtual-timer INTID 19')
    memory = {**candidate, 'previous_loaded_span_bytes': old_span['memory_bytes'],
              'previous_virtual_start': old_span['virtual_start'],
              'virtual_base_unchanged': old_span['virtual_start'] == candidate['virtual_start'],
              'preserved_loader_window_bytes': window_bytes, 'known_payload_bytes_lower_bound': loaded_payloads,
              'virtual_timer_intid': struct.unpack('<I', timer)[0],
              'adt_sha256': sha(before.read(adt_path)), 'loader_placement_runtime_qualified': False,
              'boundary': 'Necessary byte budget only; allocator placement, runtime Data growth and service working set are not qualified.'}
    allocations = [len(fat.chain(before.files[path.casefold()]['cluster'])) * volume.BLOCK for path in (target, MENU)]
    space = space_plan(before.free_bytes, *allocations, candidate['bytes'], len(menu_after), before.cluster_bytes)
    changes = [{'esp_path': target, 'package_path': 'files' + target,
                'before_sha256': sha(old_kernel), 'before_bytes': len(old_kernel),
                'after_sha256': candidate['sha256'], 'after_bytes': candidate['bytes']},
               {'esp_path': MENU, 'package_path': 'files' + MENU,
                'before_sha256': sha(menu_before), 'before_bytes': len(menu_before),
                'after_sha256': sha(menu_after), 'after_bytes': len(menu_after)}]
    rollback = {'complete_image': str(esp_path.resolve()), 'bytes': len(before.data),
                'sha256': verification['sha256'], 'verification': str(verification_path.resolve()),
                'verification_sha256': file_sha(verification_path), 'restore_runtime_tested': False,
                'kernel_duplicate_created': False,
                'files': [{'extract_from_esp': row['esp_path'], 'restore_to_esp': row['esp_path'],
                           'bytes': row['before_bytes'], 'sha256': row['before_sha256']} for row in changes]}
    proof = {'status': 'review_required' if space['replacement_space_fits'] else 'blocked_insufficient_space',
             'scope': 'existing kernel and selected menu arguments only',
             'ci_identity': {**expected, 'profile': ci['profile'], 'upstream_commit': UPSTREAM},
             'source_manifest': ci['source_manifest'], 'raw_prelink_report_sha256': ci['raw_report_sha256'],
             'compact_input': str(kernel.resolve()),
             'raw_kernel_sha256': ci['raw_sha256'], 'compact_kernel': candidate,
             'static_qualification': ci['static_qualification'],
             'source_manifest_members_verified': ci['verified_members'], 'logging_build_id': ci['logging_build_id'],
             'logging_allocation': {'token': token, 'esp_relative_first_block': log_start,
                                    'block_count': log_count, 'owned_clusters_verified': len(owners)},
             'file_changes': changes, 'preserved_inputs': preserved, 'memory': memory, 'space': space,
             'boot_args_diff': 'boot-args-diff.json', 'rollback': 'rollback.json',
             'default_entry': ENTRY, 'shared_kernel_entries': arguments['shared_kernel_entries'],
             'shared_payload_warning': 'Other entries referencing this same kernel also use its replacement; unchanged menu text is not an independent rollback.',
             'device_accessed': False, 'device_writes': False, 'installation_performed': False,
             'installer_generated': False, 'reboot_requested': False, 'hardware_tested': False,
             'runtime_qualified': False, 'ui_observed': False}
    out.mkdir(parents=True, exist_ok=False)
    for row in changes:
        destination = out / row['package_path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        if row['esp_path'] == target:
            shutil.copyfile(kernel, destination)
        else:
            destination.write_bytes(menu_after)
        require(file_sha(destination) == row['after_sha256'], 'Output file changed while packaging')
    (out / 'rollback').mkdir()
    (out / 'rollback/unixnu.before.toml').write_bytes(menu_before)
    for name, data in (('boot-args-diff.json', arguments), ('rollback.json', rollback), ('manifest.json', proof)):
        (out / name).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    (out / 'REVIEW.txt').write_text(
        'OFFLINE REVIEW PACKAGE - NO INSTALLER\n'
        'Only the two manifest-listed files are proposed replacements. No device action was performed.\n'
        'FAT replacement is not power-loss atomic. Check space and shared-kernel-entry warnings.\n'
        'Use the referenced complete ESP backup for file-level recovery; no old kernel copy was created.\n'
        'Review live device identity/state and installation scope in a separately authorized session.\n'
        'CI/static ABI and raw-to-compact equality do not prove hardware boot, rendered UI or input.\n', encoding='ascii')
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('ci-dir', 'compact-dir', 'esp', 'backup-verification', 'out'):
        parser.add_argument('--' + option, required=True, type=Path)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--head-sha', required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True, help='independently recorded source-manifest SHA')
    parser.add_argument('--notifications', choices=('on', 'off'), required=True)
    args = parser.parse_args(argv)
    expected = {'run_id': args.run_id, 'run_attempt': args.attempt, 'head_sha': args.head_sha,
                'inputs_sha256': args.input_sha256, 'manifest_sha256': args.manifest_sha256}
    try:
        result = prepare_package(ci_dir=args.ci_dir, compact_dir=args.compact_dir, esp_path=args.esp,
                                 verification_path=args.backup_verification, out=args.out, expected=expected,
                                 notifications=args.notifications == 'on')
    except (ValueError, KeyError, OSError, struct.error) as error:
        parser.exit(2, 'nabu_hardware_package: ' + str(error) + '\n')
    print(json.dumps({'out': str(args.out.resolve()), 'status': result['status'], 'device_accessed': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
