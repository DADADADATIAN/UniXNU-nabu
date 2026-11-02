#!/usr/bin/env python3
"""Derive rebased IOAcceleratorES bindings from the audited 21H16 ABI.

This is a static analysis tool. It reads the original 21H16 kernelcache and the
audited ABI contract for com.apple.iokit.IOGPUFamily, verifies every address
the contract names against the original instruction bytes, locates the same
module inside a NativePrelink candidate, translates the three mangled binding
addresses through the candidate's actual segment extents, re-verifies that the
candidate bytes are identical to the original bytes, and emits an assembler
binding file plus a machine-readable report. It never modifies either image and
never claims that the missing runtime contracts are resolved.

The 32-byte entry window is not a guess: every sha256 recorded in the audited
ABI's "original_entry_sha256" is exactly the digest of those 32 bytes at the
recorded address in device_bringup/out/kernelcache-21H16.decompressed.

Address translation follows scripts/nabu_display_bindings.py: the module object
is parsed from the original kernelcache, the candidate report's "extents" give
the final position of each copied segment, and a raw VA maps to
final_segment_va + (raw_va - original_segment_va). No fixed slide is added to
an address; --slide only has to agree with the slide the report recorded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

MODULE_ID = 'com.apple.iokit.IOGPUFamily'
# Every sha256 in the audited ABI's original_entry_sha256 is the digest of exactly
# this many bytes at the recorded address; verified against the 21H16 kernelcache.
ENTRY_WINDOW = 0x20
VTABLE_TAIL = 24
METACLASS_ZERO = 0x40
KEXT_BUNDLE = 11
DEFAULT_SLIDE = -0x1360000
# Tracked beside the header it describes. The audit directory is ignored by Git,
# so it cannot be a build input.
DEFAULT_ABI = Path(__file__).resolve().parents[1] / 'gpu/a640/ioaccelerator-base-abi.json'
# (mangled symbol, ABI JSON field, index into a list field)
SYMBOLS = (
    ('__ZN15IOAcceleratorESC2EPK11OSMetaClass', 'protected_compatible_constructor_aliases', 0),
    ('__ZN15IOAcceleratorESD2Ev', 'nondeleting_destructor', None),
    ('__ZN15IOAcceleratorES10gMetaClassE', 'metaclass', None),
)
BINDINGS_FILE = 'original-accelerator-bindings.S'
REPORT_FILE = 'adreno-bindings.json'


class DiagnosticError(Exception):
    """A fail-closed verification error with machine-readable context."""

    def __init__(self, message, **context):
        super().__init__(message)
        self.context = context


def repo_root():
    return Path(__file__).resolve().parents[4]


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def load_native_prelink(explicit):
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    root = repo_root()
    here = Path(__file__).resolve()
    candidates += [
        here.parents[1] / 'kits/NativePrelink',
        here.parents[1].parent / 'kits/NativePrelink',
        root / 'device_bringup/ipados17_inputs/tools/NativePrelink-3380d300',
        root / 'project_audit/unixnu-nabu-port-20261023/submodules/kits/NativePrelink',
    ]
    for candidate in candidates:
        if (candidate / 'native_prelink.py').is_file():
            sys.path.insert(0, str(candidate))
            import native_prelink
            return native_prelink, candidate
    raise DiagnosticError('NativePrelink not found; pass --native-prelink')


def read_va(image, data, va, length):
    at = native_prelink.backed_offset(image['segments'], va, length, len(data))
    return data[at:at + length]


def component_module(data, image, identifier):
    info = next((s for s in image['segments'] if s['name'] == '__PRELINK_INFO'), None)
    if info is None:
        raise DiagnosticError('kernelcache has no __PRELINK_INFO segment')
    entries = native_prelink.unserialize_xml(
        read_va(image, data, info['va'], info['filesize']))['_PrelinkInfoDictionary']
    matches = [e for e in entries if e.get('CFBundleIdentifier') == identifier]
    if len(matches) != 1:
        raise DiagnosticError(f'{identifier} appears {len(matches)} times in the prelink metadata')
    entry = matches[0]
    load = entry.get('_PrelinkExecutableLoadAddr')
    if not load or not entry.get('_PrelinkExecutableSize'):
        raise DiagnosticError(f'{identifier} has no prelinked executable')
    module = native_prelink.macho(
        data, native_prelink.backed_offset(image['segments'], load, 32, len(data)))
    if module['kind'] != KEXT_BUNDLE:
        raise DiagnosticError(f'{identifier} is not an MH_KEXT_BUNDLE component')
    return entry, module


def adrp_target(pc, word):
    immediate = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return (pc & ~4095) + (immediate << 12)


def add_immediate(word):
    return ((word >> 10) & 0xfff) << ((word >> 22) & 3)


def decode_ctor_vptr(data, image, pc, window=0x20):
    """Decode the vtable pointer a constructor materializes and stores to [x0]."""
    raw = read_va(image, data, pc, window)
    for offset in range(0, window - 8, 4):
        adrp, add = struct.unpack_from('<2I', raw, offset)
        if adrp & 0x9f00001f != 0x90000008 or add & 0xffc003ff != 0x91000108:
            continue
        target = adrp_target(pc + offset, adrp) + add_immediate(add)
        for later in range(offset + 8, window - 3, 4):
            if struct.unpack_from('<I', raw, later)[0] == 0xf9000008:
                return target
    raise DiagnosticError(f'no constructor vtable store at {pc:#x}')


def decode_meta_class_getter(data, image, pc):
    """Decode `adrp x0, page; add x0, x0, #imm; ret` into the returned object."""
    words = struct.unpack('<3I', read_va(image, data, pc, 12))
    if (words[0] & 0x9f00001f != 0x90000000
            or words[1] & 0xffc003ff != 0x91000000
            or words[2] != 0xd65f03c0):
        raise DiagnosticError(f'{pc:#x} is not an adrp/add/ret class-object accessor')
    return adrp_target(pc, words[0]) + add_immediate(words[1])


def read_table(data, image, vptr, slots):
    values = struct.unpack('<%dQ' % slots, read_va(image, data, vptr, slots * 8))
    if not all(values):
        raise DiagnosticError(f'Vtable {vptr:#x} has a null slot')
    if read_va(image, data, vptr + slots * 8, VTABLE_TAIL) != bytes(VTABLE_TAIL):
        raise DiagnosticError(
            f'Vtable {vptr:#x} does not end at a {VTABLE_TAIL}-byte zero boundary')
    return values


def parse_hex(value, label):
    if not isinstance(value, str):
        raise DiagnosticError(f'{label} is not a hexadecimal string: {value!r}')
    try:
        return int(value, 16)
    except ValueError:
        raise DiagnosticError(f'{label} is not a hexadecimal address: {value!r}')


def abi_hex(abi, key):
    if key not in abi:
        raise DiagnosticError(f'ABI JSON field {key} is missing')
    return parse_hex(abi[key], f'ABI JSON field {key}')


def abi_hex_list(abi, key):
    values = abi.get(key)
    if not isinstance(values, list) or not values:
        raise DiagnosticError(f'ABI JSON field {key} is missing or not a non-empty list')
    return [parse_hex(item, f'ABI JSON field {key} entry') for item in values]


def abi_int(abi, key):
    value = abi.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise DiagnosticError(f'ABI JSON field {key} is missing or not an integer')
    return value


def abi_digest(abi, key):
    value = abi.get(key)
    if not isinstance(value, str) or len(value) != 64:
        raise DiagnosticError(f'ABI JSON field {key} is not a sha256 hex digest')
    try:
        int(value, 16)
    except ValueError:
        raise DiagnosticError(f'ABI JSON field {key} is not hexadecimal')
    return value


def load_abi(path):
    if not path.is_file():
        raise DiagnosticError(f'ABI JSON not found: {path}; pass --abi')
    try:
        abi = json.loads(path.read_text(encoding='utf-8'))
    except ValueError as error:
        raise DiagnosticError(f'ABI JSON is not valid JSON: {path}: {error}')
    if not isinstance(abi, dict):
        raise DiagnosticError(f'ABI JSON is not an object: {path}')
    return abi


def module_segment_for(module, va, length, label):
    matches = [s for s in module['segments']
               if s['size'] and s['va'] <= va and va + length <= s['va'] + s['size']]
    if len(matches) != 1:
        raise DiagnosticError(
            f'{label} {va:#x}+{length:#x} is not wholly inside one {MODULE_ID} segment')
    return matches[0]


def verify_original_abi(data, image, module, abi):
    text = next((s for s in module['segments'] if s['name'] == '__TEXT_EXEC'), None)
    if text is None or not text['filesize']:
        raise DiagnosticError(f'{MODULE_ID} has no backed __TEXT_EXEC segment')
    text_sha = sha256_bytes(read_va(image, data, text['va'], text['filesize']))
    expected_text_sha = abi_digest(abi, 'original_iogpu_text_sha256')
    if text_sha != expected_text_sha:
        raise DiagnosticError(
            f'{MODULE_ID} __TEXT_EXEC sha256 mismatch: {text_sha}; the audited ABI names '
            f'{expected_text_sha}, so this kernelcache is not the audited original')

    vptr = abi_hex(abi, 'vptr')
    slots = abi_int(abi, 'virtual_entries')
    dtor = abi_hex(abi, 'nondeleting_destructor')
    get_meta_class = abi_hex(abi, 'get_meta_class')
    metaclass = abi_hex(abi, 'metaclass')
    aliases = abi_hex_list(abi, 'protected_compatible_constructor_aliases')
    instance_bytes = abi_int(abi, 'instance_bytes')

    recorded = abi.get('original_entry_sha256')
    if not isinstance(recorded, dict) or not recorded:
        raise DiagnosticError('ABI JSON field original_entry_sha256 is missing or not an object')
    entries = {}
    for address_hex, digest in sorted(recorded.items()):
        va = parse_hex(address_hex, 'ABI entry address')
        if not isinstance(digest, str) or len(digest) != 64:
            raise DiagnosticError(f'ABI entry hash for {address_hex} is not a sha256 digest')
        try:
            int(digest, 16)
        except ValueError:
            raise DiagnosticError(f'ABI entry hash for {address_hex} is not hexadecimal')
        module_segment_for(module, va, ENTRY_WINDOW, 'ABI entry')
        window = read_va(image, data, va, ENTRY_WINDOW)
        actual = sha256_bytes(window)
        if actual != digest:
            raise DiagnosticError(
                f'ABI entry bytes at {va:#x} do not match the original image: '
                f'sha256 {actual} != recorded {digest}')
        entries[hex(va)] = {
            'address': hex(va),
            'window_bytes': ENTRY_WINDOW,
            'sha256': actual,
            'instruction_words': ['0x%08x' % word
                                  for word in struct.unpack('<%dI' % (ENTRY_WINDOW // 4), window)],
            'verified': True,
        }

    for alias in aliases:
        if hex(alias) not in entries:
            raise DiagnosticError(f'ABI does not record entry bytes for constructor alias {alias:#x}')
    if hex(dtor) not in entries:
        raise DiagnosticError(f'ABI does not record entry bytes for the destructor {dtor:#x}')
    if hex(get_meta_class) not in entries:
        raise DiagnosticError(f'ABI does not record entry bytes for get_meta_class {get_meta_class:#x}')

    module_segment_for(module, vptr, slots * 8 + VTABLE_TAIL, 'ABI vtable')
    values = read_table(data, image, vptr, slots)
    if values[0] != dtor:
        raise DiagnosticError(f'Vtable slot 0 is {values[0]:#x}, not the audited destructor {dtor:#x}')
    if values[7] != get_meta_class:
        raise DiagnosticError(
            f'Vtable slot 7 is {values[7]:#x}, not the audited get_meta_class {get_meta_class:#x}')

    for alias in aliases:
        stored = decode_ctor_vptr(data, image, alias)
        if stored != vptr:
            raise DiagnosticError(
                f'Constructor {alias:#x} stores vtable {stored:#x}, not the audited vtable {vptr:#x}')

    if metaclass % 8:
        raise DiagnosticError(f'ABI metaclass object {metaclass:#x} is not 8-byte aligned')
    module_segment_for(module, metaclass, METACLASS_ZERO, 'ABI metaclass object')
    if read_va(image, data, metaclass, METACLASS_ZERO) != bytes(METACLASS_ZERO):
        raise DiagnosticError(f'ABI metaclass object {metaclass:#x} is not zero-initialized')
    returned = decode_meta_class_getter(data, image, get_meta_class)
    if returned != metaclass:
        raise DiagnosticError(
            f'get_meta_class {get_meta_class:#x} returns {returned:#x}, not the audited '
            f'metaclass object {metaclass:#x}')

    return {
        'segments': [{'name': s['name'], 'va': hex(s['va']), 'size': hex(s['size'])}
                     for s in module['segments'] if s['size']],
        'text': {'segment': '__TEXT_EXEC', 'va': hex(text['va']),
                 'size': hex(text['filesize']), 'sha256': text_sha},
        'vtable': {'va': hex(vptr), 'slots': slots,
                   'slot0': hex(values[0]), 'slot7': hex(values[7]),
                   'tail_zero_bytes': VTABLE_TAIL},
        'virtual_entries': slots,
        'metadata_overrides': abi.get('metadata_overrides'),
        'reported_instance_bytes': instance_bytes,
        'constructor': {'selected': hex(aliases[0]),
                        'aliases': [hex(alias) for alias in aliases],
                        'vptr_store': hex(vptr)},
        'nondeleting_destructor': hex(dtor),
        'get_meta_class': hex(get_meta_class),
        'metaclass': {'object': hex(metaclass), 'zero_bytes': METACLASS_ZERO,
                      'getter_returns_object': True},
        'entry_sha256': entries,
        'binding_raw': {
            SYMBOLS[0][0]: aliases[0],
            SYMBOLS[1][0]: dtor,
            SYMBOLS[2][0]: metaclass,
        },
    }


def load_candidate_report(path):
    if not path.is_file():
        raise DiagnosticError(f'candidate report not found: {path}; pass --report')
    try:
        report = json.loads(path.read_text(encoding='utf-8'))
    except ValueError as error:
        raise DiagnosticError(f'candidate report is not valid JSON: {path}: {error}')
    if not isinstance(report, dict):
        raise DiagnosticError(f'candidate report is not an object: {path}')
    return report


def candidate_translation(candidate_bytes, candidate_image, candidate_path, report,
                          report_path, kernel_sha, slide, module, entry, expected_text_sha):
    """Map original module VAs onto the candidate's actual segment extents."""
    candidate_sha = sha256_bytes(candidate_bytes)
    if report.get('candidate_sha256') != candidate_sha:
        raise DiagnosticError(
            f'candidate report hash does not match the candidate image: report says '
            f'{report.get("candidate_sha256")!r}, image is {candidate_sha}')
    if report.get('original_sha256') != kernel_sha:
        raise DiagnosticError(
            f'candidate report was built from a different kernelcache: report says '
            f'{report.get("original_sha256")!r}, --kernelcache is {kernel_sha}')
    if report.get('slide') != slide:
        raise DiagnosticError(
            f'candidate report slide {report.get("slide")!r} does not match --slide {slide:#x}')

    components = report.get('components')
    if not isinstance(components, list):
        raise DiagnosticError(f'candidate report {report_path} has no components list')
    if MODULE_ID not in components:
        listed = ', '.join(sorted(str(item) for item in components)) or '<none>'
        raise DiagnosticError(
            f'candidate does not contain {MODULE_ID}: {report_path} lists {len(components)} '
            f'emitted components ({listed}) and {MODULE_ID} is not one of them. Rebuild the '
            f'candidate with --root {MODULE_ID}; the pinned emitter only copies declared roots '
            f'and their declared OSBundleLibraries dependencies.',
            original_abi_verified=True,
            candidate_component='absent',
            candidate_report=str(report_path))

    text_hashes = report.get('original_executable_sha256')
    if not isinstance(text_hashes, dict):
        raise DiagnosticError(
            f'candidate report {report_path} has no original_executable_sha256 object')
    actual_text_sha = text_hashes.get(MODULE_ID)
    if actual_text_sha != expected_text_sha:
        raise DiagnosticError(
            f'candidate report executable hash for {MODULE_ID} is {actual_text_sha!r}, not '
            f'the audited {expected_text_sha}')

    raw_segments = {s['name']: s for s in module['segments'] if s['size']}
    final_segments = {}
    for final in report.get('extents', []):
        if not isinstance(final, dict) or final.get('module') != MODULE_ID:
            continue
        if not isinstance(final.get('va'), int) or not isinstance(final.get('size'), int):
            raise DiagnosticError(
                f'candidate report extent for {final.get("segment")!r} of {MODULE_ID} '
                f'is not a pair of integers')
        final_segments[final['segment']] = final
    missing = sorted(set(raw_segments) - set(final_segments))
    if missing:
        raise DiagnosticError(
            f'candidate report has no final extent for {MODULE_ID} segment(s) {missing}; '
            f'candidate virtual addresses cannot be derived',
            original_abi_verified=True,
            candidate_component='extents_missing',
            candidate_report=str(report_path))

    def translate(va):
        for name, segment in raw_segments.items():
            if segment['va'] <= va < segment['va'] + segment['size']:
                final = final_segments[name]
                return final['va'] + (va - segment['va'])
        raise DiagnosticError(f'Address {va:#x} is outside {MODULE_ID}')

    load = entry['_PrelinkExecutableLoadAddr']
    candidate_load = translate(load)
    header = native_prelink.macho(
        candidate_bytes, native_prelink.backed_offset(
            candidate_image['segments'], candidate_load, 32, len(candidate_bytes)))
    if header['kind'] != KEXT_BUNDLE:
        raise DiagnosticError(
            f'candidate module header at {candidate_load:#x} is not an MH_KEXT_BUNDLE')
    header_names = [s['name'] for s in header['segments']]
    if header_names != [s['name'] for s in module['segments']]:
        raise DiagnosticError(
            f'candidate module header segments {header_names} differ from the original '
            f'{[s["name"] for s in module["segments"]]}')

    extents = {}
    for name, segment in raw_segments.items():
        final = final_segments[name]
        header_segment = next(s for s in header['segments'] if s['name'] == name)
        if header_segment['va'] != final['va'] or header_segment['size'] != final['size']:
            raise DiagnosticError(
                f'candidate report extent for {name} is {final["va"]:#x}+{final["size"]:#x} '
                f'but the candidate Mach-O header says {header_segment["va"]:#x}+'
                f'{header_segment["size"]:#x}; the report is not the candidate image')
        if translate(segment['va']) != final['va']:
            raise DiagnosticError(f'segment {name} does not translate to its reported extent')
        extents[name] = {
            'original_va': hex(segment['va']),
            'candidate_va': hex(final['va']),
            'size': hex(final['size']),
            'header_matches_report': True,
        }

    info = {
        'image': str(candidate_path),
        'report': str(report_path),
        'candidate_sha256': candidate_sha,
        'slide': slide,
        'components': len(components),
        'text_sha256': actual_text_sha,
        'extents': extents,
        'module_header_va': hex(candidate_load),
    }
    return translate, info


def compare_bindings(expected, globs, entries):
    problems = []
    missing = sorted(set(expected) - set(entries))
    if missing:
        problems.append(f'missing .set for {missing}')
    extra = sorted(set(entries) - set(expected))
    if extra:
        problems.append(f'unexpected .set for {extra}')
    for name in sorted(set(expected) & set(entries)):
        if entries[name] != expected[name]:
            problems.append(f'{name}: file {entries[name]:#x} != derived {expected[name]:#x}')
    if set(globs) != set(expected):
        problems.append(f'.globl symbols {sorted(set(globs))} != expected {sorted(set(expected))}')
    return problems


def parse_bindings(path):
    if not path.is_file():
        raise DiagnosticError(f'bindings file not found: {path}')
    globs, entries = set(), {}
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        stripped = line.split('#', 1)[0].strip()
        if not stripped or stripped == '.text':
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            raise DiagnosticError(f'{path}:{number}: malformed directive: {line!r}')
        directive, rest = parts[0], parts[1].strip()
        if directive == '.globl':
            globs.add(rest)
        elif directive == '.set':
            symbol, separator, value = rest.partition(',')
            symbol, value = symbol.strip(), value.strip()
            if not separator or not symbol or not value:
                raise DiagnosticError(f'{path}:{number}: malformed .set line: {line!r}')
            if symbol in entries:
                raise DiagnosticError(f'{path}:{number}: duplicate .set for {symbol}')
            try:
                entries[symbol] = int(value, 0)
            except ValueError:
                raise DiagnosticError(f'{path}:{number}: .set value {value!r} is not an integer')
        else:
            raise DiagnosticError(f'{path}:{number}: unexpected directive {directive!r}')
    return globs, entries


def render_bindings(bindings):
    lines = []
    for name in sorted(bindings):
        lines.append(f'.globl {name}')
        lines.append(f'.set {name}, {bindings[name]:#x}')
    return '\n'.join(lines) + '\n'


def run(args):
    global native_prelink
    abi_path = args.abi or DEFAULT_ABI
    abi = load_abi(abi_path)
    if args.predict:
        return predict(args, abi, abi_path)
    native_prelink, tool_dir = load_native_prelink(args.native_prelink)

    if not args.kernelcache.is_file():
        raise DiagnosticError(f'kernelcache not found: {args.kernelcache}')
    if args.candidate is None:
        raise DiagnosticError('--candidate is required unless --predict is given')
    if not args.candidate.is_file():
        raise DiagnosticError(f'candidate not found: {args.candidate}')
    if args.report is None:
        args.report = args.candidate.with_suffix('.json')
    report_data = load_candidate_report(args.report)

    data = args.kernelcache.read_bytes()
    kernel_sha = sha256_bytes(data)
    image = native_prelink.macho(data)
    entry, module = component_module(data, image, MODULE_ID)
    original = verify_original_abi(data, image, module, abi)
    original['version'] = entry.get('CFBundleVersion')
    original['executable_load_addr'] = hex(entry['_PrelinkExecutableLoadAddr'])

    candidate_bytes = args.candidate.read_bytes()
    candidate_image = native_prelink.macho(candidate_bytes)
    translate, candidate = candidate_translation(
        candidate_bytes, candidate_image, args.candidate, report_data, args.report,
        kernel_sha, args.slide, module, entry, original['text']['sha256'])

    byte_equality = {}
    for address_hex in original['entry_sha256']:
        raw_va = int(address_hex, 16)
        candidate_va = translate(raw_va)
        original_window = read_va(image, data, raw_va, ENTRY_WINDOW)
        candidate_window = read_va(candidate_image, candidate_bytes, candidate_va, ENTRY_WINDOW)
        if candidate_window != original_window:
            difference = next(index for index, (left, right)
                              in enumerate(zip(original_window, candidate_window))
                              if left != right)
            raise DiagnosticError(
                f'candidate bytes at {candidate_va:#x} (from {raw_va:#x}) differ from the '
                f'original image at window offset {difference:#x}: candidate '
                f'{candidate_window[difference]:#04x} != original {original_window[difference]:#04x}')
        byte_equality[address_hex] = {
            'original_va': hex(raw_va),
            'candidate_va': hex(candidate_va),
            'sha256': sha256_bytes(candidate_window),
            'identical': True,
        }

    metaclass_va = translate(int(original['metaclass']['object'], 16))
    if read_va(candidate_image, candidate_bytes, metaclass_va,
               METACLASS_ZERO) != bytes(METACLASS_ZERO):
        raise DiagnosticError(
            f'candidate metaclass object {metaclass_va:#x} is not {METACLASS_ZERO:#x} zero bytes')
    returned = decode_meta_class_getter(
        candidate_bytes, candidate_image, translate(int(original['get_meta_class'], 16)))
    if returned != metaclass_va:
        raise DiagnosticError(
            f'candidate get_meta_class returns {returned:#x}, not the translated object '
            f'{metaclass_va:#x}')

    candidate_vtable_va = translate(int(original['vtable']['va'], 16))
    candidate_table = read_table(
        candidate_bytes, candidate_image, candidate_vtable_va, original['virtual_entries'])
    for slot, raw in ((0, original['nondeleting_destructor']),
                      (7, original['get_meta_class'])):
        expected = translate(int(raw, 16))
        if candidate_table[slot] != expected:
            raise DiagnosticError(
                f'candidate vtable slot {slot} is {candidate_table[slot]:#x}, not the '
                f'translated {raw} ({expected:#x})')

    bindings = {name: translate(raw) for name, raw in original['binding_raw'].items()}
    candidate['byte_equality'] = byte_equality
    candidate['vtable'] = {
        'va': hex(candidate_vtable_va),
        'slot0': hex(candidate_table[0]),
        'slot7': hex(candidate_table[7]),
        'rebound_to_translated_targets': True,
    }
    candidate['metaclass'] = {
        'object': hex(metaclass_va),
        'zero_bytes': METACLASS_ZERO,
        'getter_returns_object': True,
    }

    report = {
        'status': 'ok',
        'mode': 'validate' if args.check_bindings is not None else 'generate',
        'module': MODULE_ID,
        'module_version': entry.get('CFBundleVersion'),
        'kernelcache': str(args.kernelcache),
        'kernelcache_sha256': kernel_sha,
        'abi': {
            'path': str(abi_path),
            'text_sha256': abi['original_iogpu_text_sha256'],
            'entry_window_bytes': ENTRY_WINDOW,
        },
        'original': original,
        'address_space': 'candidate',
        'candidate': candidate,
        'bindings': {name: hex(value) for name, value in bindings.items()},
        'bindings_scope': 'candidate_segment_extents_only',
        'checks': {
            'original_text_sha256': 'passed',
            'original_entry_bytes': 'passed',
            'original_vtable': 'passed',
            'original_constructor_vptr_store': 'passed',
            'original_metaclass_getter': 'passed',
            'candidate_component_present': 'passed',
            'candidate_header_matches_report_extents': 'passed',
            'candidate_byte_equality': 'passed',
            'candidate_vtable_rebinding': 'passed',
            'candidate_metaclass_getter': 'passed',
        },
        'runtime_qualified': False,
        'images_modified': False,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.check_bindings is not None:
        globs, entries = parse_bindings(args.check_bindings)
        problems = compare_bindings(bindings, globs, entries)
        report['bindings_file'] = str(args.check_bindings)
        report['bindings_file_values'] = {name: hex(value) for name, value in entries.items()}
        report['bindings_validated'] = not problems
        report['bindings_problems'] = problems
        report['status'] = 'ok' if not problems else 'mismatch'
    else:
        (args.output_dir / BINDINGS_FILE).write_text(
            render_bindings(bindings), encoding='utf-8')
        report['bindings_file'] = str(args.output_dir / BINDINGS_FILE)

    report_path = args.output_dir / REPORT_FILE
    report['report_file'] = str(report_path)
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report



def abi_address(abi, field, index):
    """Return one audited original address from the ABI JSON."""
    value = abi.get(field)
    if index is not None:
        if not isinstance(value, list) or len(value) <= index:
            raise DiagnosticError(f'audited ABI field {field} has no entry {index}')
        value = value[index]
    if not isinstance(value, str) or not value.startswith('0x'):
        raise DiagnosticError(f'audited ABI field {field} is not a hex address')
    try:
        return int(value, 16)
    except ValueError:
        raise DiagnosticError(f'audited ABI field {field} is not a hex address: {value}')


def predict(args, abi, abi_path):
    """Emit the bindings the audited ABI implies under the declared slide.

    This is a prediction, not a derivation. It exists because the archive must
    exist before the kernel links, so no candidate is available yet. The
    collector re-derives the same three aliases from the finished candidate and
    the GPU qualifier refuses a candidate whose linked symbol table disagrees,
    so these values can never be installed as a verified result.
    """
    if not args.kernelcache.is_file():
        raise DiagnosticError(f'kernelcache not found: {args.kernelcache}')
    digest = sha256_bytes(args.kernelcache.read_bytes())
    bindings = {name: abi_address(abi, field, index) + args.slide
                for name, field, index in SYMBOLS}
    checks = {
        'abi_instance_bytes': 'passed' if abi.get('instance_bytes') == 136 else 'failed',
        'abi_virtual_entries': 'passed' if abi.get('virtual_entries') == 168 else 'failed',
        'abi_metadata_overrides': 'passed' if abi.get('metadata_overrides') == [0, 1, 7] else 'failed',
    }
    if any(value != 'passed' for value in checks.values()):
        raise DiagnosticError('audited ABI shape changed: ' + json.dumps(checks))
    report = {
        'status': 'ok',
        'mode': 'predict',
        'module': MODULE_ID,
        'kernelcache': str(args.kernelcache),
        'kernelcache_sha256': digest,
        'abi': {'path': str(abi_path),
                'text_sha256': abi_digest(abi, 'original_iogpu_text_sha256'),
                'entry_window_bytes': ENTRY_WINDOW},
        'original': {'reported_instance_bytes': abi.get('instance_bytes'),
                     'virtual_entries': abi.get('virtual_entries'),
                     'metadata_overrides': abi.get('metadata_overrides')},
        'address_space': 'predicted',
        'candidate': None,
        'bindings': {name: hex(value) for name, value in bindings.items()},
        'bindings_scope': 'predicted_from_audited_abi_slide',
        'checks': checks,
        'runtime_qualified': False,
        'images_modified': False,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / BINDINGS_FILE).write_text(render_bindings(bindings), encoding='utf-8')
    report['bindings_file'] = str(args.output_dir / BINDINGS_FILE)
    report_path = args.output_dir / REPORT_FILE
    report['report_file'] = str(report_path)
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--kernelcache', required=True, type=Path,
                        help='original decompressed 21H16 kernelcache')
    parser.add_argument('--candidate', type=Path,
                        help='candidate kernel Mach-O from NativePrelink; required unless predicting')
    parser.add_argument('--predict', action='store_true',
                        help='emit the aliases the audited ABI implies under --slide, without a candidate')
    parser.add_argument('--report', type=Path,
                        help='candidate prelink report/kernel.json (default: candidate with .json)')
    parser.add_argument('--abi', type=Path,
                        help=f'audited ABI JSON (default: <repo>/{DEFAULT_ABI})')
    parser.add_argument('--slide', type=lambda value: int(value, 0), default=DEFAULT_SLIDE,
                        help='expected prelink slide; must match the report (default: -0x1360000)')
    parser.add_argument('--native-prelink', type=Path,
                        help='NativePrelink directory holding native_prelink.py')
    parser.add_argument('--output-dir', required=True, type=Path,
                        help=f'directory for {BINDINGS_FILE} and {REPORT_FILE}')
    parser.add_argument('--check-bindings', type=Path,
                        help='validate an existing bindings file without emitting a new one')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        report = run(args)
    except DiagnosticError as error:
        diagnostic = {'status': 'error', 'error': str(error)}
        diagnostic.update(error.context)
        print(json.dumps(diagnostic, indent=2), file=sys.stderr)
        return 2
    except (ValueError, OSError) as error:
        print(json.dumps({'status': 'error', 'error': str(error)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
