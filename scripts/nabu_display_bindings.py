#!/usr/bin/env python3
"""Derive the 21H16 IOMobileFramebufferLegacy ABI and emit fail-closed bindings.

This is a static analysis tool.  It reads the original kernelcache (and an
optional pass-1 reference candidate), validates the expected vtable/constructor
structure, and emits a machine-readable contract plus an assembly binding file.
It never modifies the original images and never claims that the missing
getter/swap/user-client contracts are resolved.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

KERNELCACHE_SHA256 = 'f7d1952c7a21633d212eccf288e77444fff0cc86976db5de292f6819c2ffa1b2'
FAMILY_TEXT_SHA256 = 'f216f3ad806f811575926f2f5f7e69fa9d700af9cd2c37575463aa0bb3d7ee85'
FAMILY_ID = 'com.apple.iokit.IOMobileGraphicsFamily'
IOSURFACE_ID = 'com.apple.iokit.IOSurface'
IOSURFACE_VERSION = '352.50.1'
IOSURFACE_TEXT_SHA256 = '1166365c0e6e11c31b82d8d5808e1ed69d3449a9086336bee18fea2375e10031'
# Raw pre-slide VAs from the 21H16 static pass.  Each numeric getter is a
# two-instruction `ldr {x,w}0,[x0,#offset]; ret`; descriptor is the same
# object getter at +0x30.  The duplicate forms found by the audit are rejected.
IOSURFACE_GETTERS = [
    {'name': 'descriptor', 'va': 0xfffffff005b8fad0, 'offset': 0x30, 'width': 'x',
     'symbol': '_native_legacy_surface_descriptor'},
    {'name': 'width', 'va': 0xfffffff005b8fbbc, 'offset': 0x58, 'width': 'x',
     'symbol': '_native_legacy_surface_width'},
    {'name': 'height', 'va': 0xfffffff005b8fbc4, 'offset': 0x60, 'width': 'x',
     'symbol': '_native_legacy_surface_height'},
    {'name': 'stride', 'va': 0xfffffff005b8fbd4, 'offset': 0x68, 'width': 'x',
     'symbol': '_native_legacy_surface_stride'},
    {'name': 'allocation', 'va': 0xfffffff005b8fbfc, 'offset': 0x90, 'width': 'x',
     'symbol': '_native_legacy_surface_allocation'},
    {'name': 'format', 'va': 0xfffffff005b8fbac, 'offset': 0x80, 'width': 'w',
     'symbol': '_native_legacy_surface_format'},
    {'name': 'planes', 'va': 0xfffffff005b8fbf4, 'offset': 0x98, 'width': 'w',
     'symbol': '_native_legacy_surface_planes'},
]
EXPECTED_SLOTS = {'base': 262, 'service': 262, 'legacy': 358}
EXPECTED_PURE = [211, 213, 245, 246, 306, 307, 337, 338, 345]
EXPECTED_BASE_SERVICE_CHANGED = [0, 1, 7]
EXPECTED_CHANGED_LT168 = [0, 1, 7, 14, 21, 44, 79, 85, 86, 87, 111, 141, 155]
EXPECTED_LEGACY_CTOR = 0xfffffff005cc95cc
EXPECTED_LEGACY_VPTR = 0xfffffff006d58970
EXPECTED_SERVICE_CTOR = 0xfffffff005cbe510
EXPECTED_BASE_CTOR = 0xfffffff005cbe318
EXPECTED_DTOR = 0xfffffff005cc9618
EXPECTED_SERVICE_DTOR = 0xfffffff005cbe55c
EXPECTED_METACLASS_CTOR = 0xfffffff005cc967c
EXPECTED_GMETACLASS = 0xfffffff007afe840
EXPECTED_METACLASS_VPTR = 0xfffffff006d594b8
EXPECTED_PARENT = 0xfffffff007afa300
EXPECTED_NAME_VA = 0xfffffff005444807
# Slot 249: nullable width/height outputs, reading uint32 fields +5808/+5812.
DIMENSIONS_ACCESSOR = bytes.fromhex(
    'ff8300d1e00f00f9e10b00f9e20700f9e80f40f9e80300f9e80b40f9080100f1'
    'e8179f1ae800003701000014e80340f908b156b9e90b40f9280100b901000014'
    'e80740f9080100f1e8179f1ae800003701000014e80340f908b556b9e90740f9'
    '280100b901000014ff830091c0035fd6')


def qualify_dimensions_accessor(code):
    if code != DIMENSIONS_ACCESSOR:
        raise ValueError('Original dimension accessor differs from the audited 21H16 body')
    return {'slot': 249, 'width_offset': 5808, 'height_offset': 5812,
            'field_bytes': 4, 'instruction_sha256': hashlib.sha256(code).hexdigest()}


def load_native_prelink(explicit):
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    root = Path(__file__).resolve().parents[4]
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
    raise SystemExit('NativePrelink not found; pass --native-prelink')


def read_va(image, data, va, length):
    at = native_prelink.backed_offset(image['segments'], va, length, len(data))
    return data[at:at + length]


def decode_ctor_vptr(data, image, pc, window=0x20):
    raw = read_va(image, data, pc, window)
    for offset in range(0, window - 11, 4):
        a, b, c = struct.unpack_from('<3I', raw, offset)
        if a & 0x9f00001f != 0x90000008:
            continue
        if b & 0xffc003ff != 0x91000108 or c != 0x91004108:
            continue
        imm = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        return (pc + offset & ~4095) + (imm << 12) + ((b >> 10) & 4095) + 16
    raise ValueError(f'No constructor vptr pattern at {pc:#x}')


def first_bl(data, image, pc, limit=0x60):
    raw = read_va(image, data, pc, limit)
    for offset in range(0, limit - 4, 4):
        word = struct.unpack_from('<I', raw, offset)[0]
        if word & 0xfc000000 != 0x94000000:
            continue
        value = word & 0x3ffffff
        return pc + offset + 4 * (value - (1 << 26) if value & (1 << 25) else value)
    raise ValueError(f'No direct call at {pc:#x}')


def read_table(data, image, vptr, slots):
    values = struct.unpack('<%dQ' % slots, read_va(image, data, vptr, slots * 8))
    if not all(values):
        raise ValueError(f'Vtable {vptr:#x} has a null slot')
    if read_va(image, data, vptr + slots * 8, 24) != bytes(24):
        raise ValueError(f'Vtable {vptr:#x} does not end at a 24-byte zero boundary')
    return values


def component_module(data, image, native_prelink, identifier):
    info = next(s for s in image['segments'] if s['name'] == '__PRELINK_INFO')
    entries = native_prelink.unserialize_xml(
        read_va(image, data, info['va'], info['filesize']))['_PrelinkInfoDictionary']
    entry = next(e for e in entries if e['CFBundleIdentifier'] == identifier)
    module = native_prelink.macho(data, native_prelink.backed_offset(
        image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(data)))
    return entry, module


def find_family_module(data, image, native_prelink):
    return component_module(data, image, native_prelink, FAMILY_ID)


def validate_getter(data, image, getter):
    """The numeric getters must be exactly `ldr {x,w}0,[x0,#offset]; ret`."""
    width = getter['width']
    unit = 8 if width == 'x' else 4
    expected = (0xf9400000 if width == 'x' else 0xb9400000) | ((getter['offset'] // unit) << 10)
    first, second = struct.unpack('<2I', read_va(image, data, getter['va'], 8))
    if first != expected or second != 0xd65f03c0:
        raise ValueError(
            f"Getter {getter['name']} at {getter['va']:#x} is not the expected "
            f"ldr/ret pair (got {first:#x}, {second:#x})")
    return {'encoding': f'0x{first:08x}', 'return': f'0x{second:08x}'}


def iterate_ctor_patterns(data, image, module):
    text = next(s for s in module['segments'] if s['name'] == '__TEXT_EXEC')
    raw = read_va(image, data, text['va'], text['filesize'])
    for offset in range(0, len(raw) - 12, 4):
        a, b, c = struct.unpack_from('<3I', raw, offset)
        if a & 0x9f00001f == 0x90000008 and b & 0xffc003ff == 0x91000108 and c == 0x91004108:
            yield text['va'] + offset


def find_legacy_ctor(data, image, module, native_prelink):
    pure = native_prelink.exports(data, image)
    names = {name: va for va, group in pure.items() for name in group}
    pure_va = names['___cxa_pure_virtual']
    matches = []
    for pattern in iterate_ctor_patterns(data, image, module):
        try:
            ctor = nearest_function_start(data, image, pattern)
            vptr = decode_ctor_vptr(data, image, ctor, window=0x20)
            values = read_table(data, image, vptr, EXPECTED_SLOTS['legacy'])
        except ValueError:
            continue
        pure_slots = [i for i, value in enumerate(values) if value == pure_va]
        if pure_slots == EXPECTED_PURE:
            matches.append((ctor, vptr, values))
    if len(matches) != 1:
        raise ValueError(f'Expected one 358-slot Legacy constructor, found {len(matches)}')
    return matches[0]


def nearest_function_start(data, image, pc, limit=0x40):
    """Walk back to the nearest `sub sp, sp, #imm` prologue."""
    start = max(0, pc - limit)
    raw = read_va(image, data, start, pc - start + 4)
    for offset in range(len(raw) - 4, -4, -4):
        word = struct.unpack_from('<I', raw, offset)[0]
        if word & 0xffc003ff == 0xd10003ff:
            return start + offset
    raise ValueError(f'No stack prologue before {pc:#x}')


def find_metaclass(data, image, module):
    target = None
    for pattern in iterate_ctor_patterns(data, image, module):
        vptr = decode_ctor_vptr(data, image, pattern)
        if vptr == EXPECTED_METACLASS_VPTR:
            ctor = nearest_function_start(data, image, pattern)
            if ctor == EXPECTED_METACLASS_CTOR:
                target = ctor
                break
    if target != EXPECTED_METACLASS_CTOR:
        raise ValueError(f'Expected metaclass constructor {EXPECTED_METACLASS_CTOR:#x}, got {target}')
    return target


def scan_metaclass_fields(data, image, module, ctor):
    """Decode the adrp/add pairs for name, parent, size and gMetaClass."""
    raw = read_va(image, data, ctor, 0x60)
    name = parent = None
    for offset in range(0, len(raw) - 8, 4):
        a, b = struct.unpack_from('<2I', raw, offset)
        # adrp x1 / add x1
        if a & 0x9f00001f == 0x90000001 and b & 0xffc003ff == 0x91000021:
            imm = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            name = (ctor + offset & ~4095) + (imm << 12) + ((b >> 10) & 4095)
        # adrp x2 / add x2
        if a & 0x9f00001f == 0x90000002 and b & 0xffc003ff == 0x91000042:
            imm = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            parent = (ctor + offset & ~4095) + (imm << 12) + ((b >> 10) & 4095)
    if name != EXPECTED_NAME_VA or parent != EXPECTED_PARENT:
        raise ValueError(f'Metaclass name/parent mismatch: {name} {parent}')
    # The class object is the x0 passed to the metaclass constructor by its
    # unique caller.
    text = next(s for s in module['segments'] if s['name'] == '__TEXT_EXEC')
    blob = read_va(image, data, text['va'], text['filesize'])
    callers = []
    for offset in range(0, len(blob) - 4, 4):
        word = struct.unpack_from('<I', blob, offset)[0]
        if word & 0xfc000000 != 0x94000000:
            continue
        value = word & 0x3ffffff
        pc = text['va'] + offset
        dst = pc + 4 * (value - (1 << 26) if value & (1 << 25) else value)
        if dst == ctor:
            callers.append(pc)
    if len(callers) != 1:
        raise ValueError(f'Expected one metaclass caller, found {len(callers)}')
    caller = callers[0]
    window = read_va(image, data, caller - 0x40, 0x48)
    class_objects = []
    for offset in range(0, len(window) - 8, 4):
        a, b = struct.unpack_from('<2I', window, offset)
        if a & 0x9f00001f == 0x90000000 and b & 0xffc003ff == 0x91000000:
            imm = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            class_objects.append(
                ((caller - 0x40 + offset) & ~4095) + (imm << 12) + ((b >> 10) & 4095))
    if len(class_objects) != 1:
        raise ValueError(f'Expected one raw gMetaClass address pair, found {len(class_objects)}')
    class_object = class_objects[0]
    if class_object != EXPECTED_GMETACLASS:
        raise ValueError(f'Expected gMetaClass {EXPECTED_GMETACLASS:#x}, got {class_object}')
    return name, parent, class_object, caller


def candidate_class_object(image, data, caller):
    """Decode and validate gMetaClass from a relocated candidate caller.

    Raw kernelcache addresses are not candidate addresses: prelink can move
    the zero-initialized class object into a different segment/extent. The
    relocated caller is authoritative for this candidate only.
    """
    window_start = caller - 0x40
    window = read_va(image, data, window_start, 0x48)
    targets = []
    for offset in range(0, len(window) - 8, 4):
        adrp, add = struct.unpack_from('<2I', window, offset)
        if adrp & 0x9f00001f != 0x90000000 or add & 0xffc003ff != 0x91000000:
            continue
        imm = ((adrp >> 5) & 0x7ffff) * 4 + ((adrp >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = window_start + offset
        targets.append(((pc & ~4095) + (imm << 12) + ((add >> 10) & 4095)))
    if len(targets) != 1:
        raise ValueError(f'Expected one candidate gMetaClass address pair, found {len(targets)}')

    target = targets[0]
    if target & 7:
        raise ValueError(f'Candidate gMetaClass {target:#x} is not 8-byte aligned')
    containing = [segment for segment in image['segments']
                  if segment['va'] <= target
                  and target + 0x40 <= segment['va'] + segment['size']]
    if len(containing) != 1:
        raise ValueError(f'Candidate gMetaClass {target:#x} is not wholly inside one mapped segment')
    if read_va(image, data, target, 0x40) != bytes(0x40):
        raise ValueError(f'Candidate gMetaClass {target:#x} is not zero-initialized')
    return target


def candidate_translation(native, kernelcache_sha, slide, identifier, text_sha, module,
                          expected_text_sha=None):
    report_path = native.with_suffix('.json')
    report = json.loads(report_path.read_text())
    candidate_sha = hashlib.sha256(native.read_bytes()).hexdigest()
    if report.get('candidate_sha256') != candidate_sha:
        raise ValueError('Candidate report hash does not match the candidate image')
    if report.get('original_sha256') != kernelcache_sha:
        raise ValueError('Candidate report was built from a different kernelcache')
    if report.get('slide') != slide:
        raise ValueError('Candidate report slide does not match --slide')
    actual_text_sha = report.get('original_executable_sha256', {}).get(identifier)
    if actual_text_sha != text_sha:
        raise ValueError(f'Candidate report text hash mismatch for {identifier}')
    if expected_text_sha is not None and actual_text_sha != expected_text_sha:
        raise ValueError(f'Candidate report text hash is not the qualified one for {identifier}')
    raw_segments = {s['name']: s for s in module['segments'] if s['size']}
    final_segments = {e['segment']: e for e in report['extents'] if e['module'] == identifier}

    def translate(va):
        for name, segment in raw_segments.items():
            if segment['va'] <= va < segment['va'] + segment['size']:
                final = final_segments.get(name)
                if final is None:
                    raise ValueError(f'No final extent for {identifier} segment {name}')
                return final['va'] + (va - segment['va'])
        raise ValueError(f'Address {va:#x} is outside {identifier}')

    return translate, {'report': str(report_path), 'image': str(native),
                       'candidate_sha256': candidate_sha, 'slide': slide,
                       'identifier': identifier, 'text_sha256': actual_text_sha}


def generate_header():
    """Opaque ABI storage for the exact 21H16 Legacy class.

    The slot names are structural; only the qualified slots may be called.
    Unknown slots remain deprecated opaque entries and are never called from
    source.
    """
    header = '''// SPDX-License-Identifier: BSD-2-Clause-Patent
// Generated from the 21H16 original IOMobileFramebufferLegacy vtable.
// Opaque ABI storage for the exact original class, not source-level access
// to its private fields. The original metadata supplies its full
// Framebuffer/Service/IOService ancestry.
#pragma once
#include <IOKit/IOService.h>
#include <libkern/libkern.h>
struct OriginalLegacySwapRequest;
class IOMobileFramebufferLegacy : public IOService {
 OSDeclareAbstractStructors(IOMobileFramebufferLegacy)
 unsigned char originalPrivate[0x18a0-sizeof(IOService)];
public:
 // Candidate convenience accessors; their object offsets are structural and
 // must be checked by the runtime observation before being trusted.
 void installBootDimensions(uint32_t width,uint32_t height) {
  *reinterpret_cast<uint32_t *>(reinterpret_cast<unsigned char *>(this)+5808)=width;
  *reinterpret_cast<uint32_t *>(reinterpret_cast<unsigned char *>(this)+5812)=height;
 }
 const OriginalLegacySwapRequest *pendingSwapRequest() const {
  const OriginalLegacySwapRequest *request=nullptr;
  memcpy(&request,reinterpret_cast<const unsigned char *>(this)+5480,sizeof(request));return request;
 }
 bool activateOnlyPendingSwap(const OriginalLegacySwapRequest *request) {
  auto self=reinterpret_cast<unsigned char *>(this);
  auto bytes=reinterpret_cast<const unsigned char *>(request);
  const void *current=nullptr,*head=nullptr,*tail=nullptr,*next=nullptr,*previous=nullptr;
  memcpy(&current,self+5472,8);memcpy(&head,self+5480,8);memcpy(&tail,self+5488,8);
  if(!request || current || head!=request)return false;
  memcpy(&next,bytes+2960,8);memcpy(&previous,bytes+2968,8);
  if(previous!=self+5480)return false;
  if(next) {
   const void *link=self+5480;
   memcpy(const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(next))+2968,&link,8);
  } else if(tail!=bytes+2960)return false;
  memcpy(self+5472,&request,8);
  if(next) {memcpy(self+5480,&next,8);}
  else {const void *empty=nullptr,*emptyTail=self+5480;memcpy(self+5480,&empty,8);memcpy(self+5488,&emptyTail,8);}
  return true;
 }
 void free() override;
 bool init(OSDictionary *properties=nullptr) override;
 IOReturn setProperties(OSObject *) override;
 void systemWillShutdown(IOOptionBits) override;
 IOService *probe(IOService *,SInt32 *) override;
 bool start(IOService *) override;
 void stop(IOService *) override;
 IOWorkLoop *getWorkLoop() const override;
 IOReturn newUserClient(task_t,void *,UInt32,IOUserClient **) override;
 IOReturn setPowerState(unsigned long,IOService *) override;
'''
    for slot in range(168, 358):
        if slot == 184:
            header += ' virtual bool isMainDisplay();\n'
        elif slot == 188:
            header += ' virtual IOReturn getDotPitch(uint32_t *);\n'
        elif slot == 213:
            header += ' virtual IOReturn supportedFrameInfo(uint32_t,uint32_t *,char *,uint32_t *)=0;\n'
        elif slot == 249:
            header += ' virtual void getDisplayDimensions(uint32_t *,uint32_t *);\n'
        elif slot == 290:
            header += ' virtual void kickSwapQueue();\n'
        elif slot == 296:
            header += ' virtual bool validateSwap(const OriginalLegacySwapRequest *);\n'
        elif slot == 301:
            header += ' virtual bool getRefreshAttributes(uint64_t *, bool);\n'
        elif slot == 295:
            header += ' virtual void completeCurrentSwap();\n'
        elif slot == 337:
            header += ' virtual IOReturn collectCompletionReports(uint32_t,void *,uint32_t *,uint32_t)=0;\n'
        elif slot == 288:
            header += ' virtual bool startHardware();\n'
        elif slot in EXPECTED_PURE:
            header += f' virtual __attribute__((noreturn)) void opaque{slot}()=0;\n'
        else:
            header += (f' virtual __attribute__((deprecated("Unclassified ABI: never call from source"))) '
                       f'void opaque{slot}();\n')
    header += ('};\nstatic_assert(sizeof(IOMobileFramebufferLegacy)==0x18a0,'
               '"Actual original instance extent");\n')
    return header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernelcache', required=True, type=Path)
    parser.add_argument('--native', type=Path,
                        help='candidate kernel.macho with matching .json; enables address translation')
    parser.add_argument('--slide', type=lambda value: int(value, 0), default=-0x1360000)
    parser.add_argument('--native-prelink', type=Path)
    parser.add_argument('--cpu-present', action='store_true',
                        help='Qualify the selected original CPU presentation contract and activation binding')
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()

    global native_prelink
    native_prelink, tool_dir = load_native_prelink(args.native_prelink)
    data = args.kernelcache.read_bytes()
    kernel_sha = hashlib.sha256(data).hexdigest()
    if kernel_sha != KERNELCACHE_SHA256:
        raise SystemExit(f'Kernelcache SHA mismatch: {kernel_sha}')
    image = native_prelink.macho(data)
    entry, module = find_family_module(data, image, native_prelink)
    text = next(s for s in module['segments'] if s['name'] == '__TEXT_EXEC')
    family_text_sha = hashlib.sha256(read_va(image, data, text['va'], text['filesize'])).hexdigest()
    if family_text_sha != FAMILY_TEXT_SHA256:
        raise SystemExit(f'Family text SHA mismatch: {family_text_sha}')
    iosurface_entry, iosurface_module = component_module(
        data, image, native_prelink, IOSURFACE_ID)
    if iosurface_entry.get('CFBundleVersion') != IOSURFACE_VERSION:
        raise SystemExit('IOSurface version does not match the qualified 21H16 input')
    iosurface_text = next(s for s in iosurface_module['segments'] if s['name'] == '__TEXT_EXEC')
    iosurface_text_sha = hashlib.sha256(
        read_va(image, data, iosurface_text['va'], iosurface_text['filesize'])).hexdigest()
    if iosurface_text_sha != IOSURFACE_TEXT_SHA256:
        raise SystemExit(f'IOSurface text SHA mismatch: {iosurface_text_sha}')
    iosurface_getters = []
    for getter in IOSURFACE_GETTERS:
        record = dict(getter)
        record.update(validate_getter(data, image, getter))
        iosurface_getters.append(record)

    legacy_ctor, legacy_vptr, legacy = find_legacy_ctor(data, image, module, native_prelink)
    dimensions = qualify_dimensions_accessor(read_va(image, data, legacy[249], len(DIMENSIONS_ACCESSOR)))
    cpu_contract = None
    if args.cpu_present:
        from nabu_cpu_abi import qualify
        cpu_contract = qualify(lambda va, size: read_va(image, data, va, size), legacy)
    if legacy_ctor != EXPECTED_LEGACY_CTOR or legacy_vptr != EXPECTED_LEGACY_VPTR:
        raise SystemExit('Locator found an unexpected Legacy constructor/vtable')
    service_ctor = first_bl(data, image, legacy_ctor)
    base_ctor = first_bl(data, image, service_ctor)
    if service_ctor != EXPECTED_SERVICE_CTOR or base_ctor != EXPECTED_BASE_CTOR:
        raise SystemExit('Constructor chain does not match the qualified 21H16 values')
    service_vptr = decode_ctor_vptr(data, image, service_ctor)
    base_vptr = decode_ctor_vptr(data, image, base_ctor)
    base = read_table(data, image, base_vptr, EXPECTED_SLOTS['base'])
    service = read_table(data, image, service_vptr, EXPECTED_SLOTS['service'])
    base_service_changed = [i for i, (a, b) in enumerate(zip(base, service)) if a != b]
    changed = [i for i, (a, b) in enumerate(zip(base, legacy)) if a != b]
    if base_service_changed != EXPECTED_BASE_SERVICE_CHANGED:
        raise SystemExit('Base/service override set changed')
    if [i for i in changed if i < 168] != EXPECTED_CHANGED_LT168 or len(changed) != 103:
        raise SystemExit('Legacy override set changed')
    dtor = EXPECTED_DTOR
    if first_bl(data, image, dtor) != EXPECTED_SERVICE_DTOR:
        raise SystemExit('Legacy destructor candidate does not call the service destructor')
    metaclass_ctor = find_metaclass(data, image, module)
    name, parent, raw_class_object, raw_caller = scan_metaclass_fields(
        data, image, module, metaclass_ctor)
    metaclass_vptr = decode_ctor_vptr(data, image, metaclass_ctor, window=0x40)
    if metaclass_vptr != EXPECTED_METACLASS_VPTR:
        raise SystemExit('Metaclass vtable mismatch')

    binding_specs = [
        ('__ZN25IOMobileFramebufferLegacyC2EPK11OSMetaClass', legacy_ctor, 'family'),
        ('__ZN25IOMobileFramebufferLegacyD2Ev', dtor, 'family'),
        ('__ZTV25IOMobileFramebufferLegacy', legacy_vptr - 16, 'family'),
        # An override still calls its original parent implementation. Its own
        # vtable slot no longer supplies that parent symbol to the builder.
        ('__ZN25IOMobileFramebufferLegacy13setPowerStateEmP9IOService', legacy[155], 'family'),
    ]
    binding_specs += [(getter['symbol'], getter['va'], 'iosurface')
                      for getter in iosurface_getters]
    if args.cpu_present:
        from nabu_cpu_abi import ACTIVE_REQUEST, DISPLAY_STATE
        binding_specs.append(('_nabu_legacy_request_active', ACTIVE_REQUEST, 'family'))
        binding_specs.append(('_nabu_legacy_display_state', DISPLAY_STATE, 'family'))
    translators = {}
    candidate = {}
    if args.native is not None:
        if not args.native.is_file():
            raise SystemExit(f'Candidate not found: {args.native}')
        translators['family'], candidate['family'] = candidate_translation(
            args.native, kernel_sha, args.slide, FAMILY_ID, family_text_sha,
            module, FAMILY_TEXT_SHA256)
        translators['iosurface'], candidate['iosurface'] = candidate_translation(
            args.native, kernel_sha, args.slide, IOSURFACE_ID, iosurface_text_sha,
            iosurface_module, IOSURFACE_TEXT_SHA256)

    class_object = raw_class_object
    if 'family' in translators:
        candidate_caller = translators['family'](raw_caller)
        class_object = candidate_class_object(
            native_prelink.macho(args.native.read_bytes()), args.native.read_bytes(),
            candidate_caller)
    binding_specs.append(
        ('__ZN25IOMobileFramebufferLegacy10gMetaClassE', class_object, 'none'))

    def address(va, component):
        return translators[component](va) if component in translators else va

    def safe_candidate(va):
        if 'family' not in translators:
            return None
        for segment in module['segments']:
            if segment['size'] and segment['va'] <= va < segment['va'] + segment['size']:
                return hex(address(va, 'family'))
        return None

    key_slots = {str(i): hex(legacy[i]) for i in
                 (0, 1, 7, 14, 21, 44, 79, 85, 86, 87, 111, 141, 155, 168,
                  211, 213, 245, 246, 306, 307, 337, 338, 345)}
    bindings = {name: address(va, component)
                for name, va, component in binding_specs}
    report = {
        'kernelcache_sha256': kernel_sha,
        'family': FAMILY_ID,
        'family_version': entry.get('CFBundleVersion'),
        'family_text_sha256': family_text_sha,
        'iosurface': {
            'identifier': IOSURFACE_ID,
            'version': iosurface_entry.get('CFBundleVersion'),
            'text_sha256': iosurface_text_sha,
            'getters': {
                getter['name']: {
                    'raw_va': hex(getter['va']),
                    'candidate_va': (hex(address(getter['va'], 'iosurface'))
                                     if 'iosurface' in translators else None),
                    'offset': hex(getter['offset']),
                    'width': getter['width'],
                    'symbol': getter['symbol'],
                    'encoding': getter['encoding'],
                    'return': getter['return'],
                    'status': 'confirmed',
                    'owner_virtual': 'unknown',
                    'invocation': 'unknown',
                } for getter in iosurface_getters
            },
            'owner_virtual': 'unknown',
            'invocation': 'unknown',
        },
        'address_space': 'candidate' if translators else 'raw',
        'candidate': candidate or None,
        'gMetaClass_binding_scope': (
            'supplied_candidate_only; other_candidates_not_checked'
            if 'family' in translators else 'raw_kernelcache_static_analysis_only'),
        'objects': {
            'base': {'ctor': hex(base_ctor), 'vptr': hex(base_vptr), 'slots': len(base)},
            'service': {'ctor': hex(service_ctor), 'vptr': hex(service_vptr), 'slots': len(service)},
            'legacy': {'ctor': hex(legacy_ctor), 'vptr': hex(legacy_vptr), 'dtor': hex(dtor),
                       'slots': len(legacy), 'instance_bytes': hex(0x18a0)},
        },
        'metaclass': {'ctor': hex(metaclass_ctor), 'vptr': hex(metaclass_vptr),
                      'object': hex(class_object), 'raw_object': hex(raw_class_object),
                      'candidate_object': (hex(class_object)
                                           if 'family' in translators else None),
                      'name_va': hex(name), 'parent': hex(parent)},
        'pure_virtual_slots': EXPECTED_PURE,
        'base_vs_service_changed': base_service_changed,
        'base_vs_legacy_changed_count': len(changed),
        'base_vs_legacy_changed_lt168': EXPECTED_CHANGED_LT168,
        'key_slots_raw': key_slots,
        'methods': [
            {'slot': i, 'raw_va': hex(legacy[i]),
             'candidate_va': safe_candidate(legacy[i])}
            for i in range(len(legacy))
        ],
        'bindings': {name: hex(va) for name, va in bindings.items()},
        'contracts': {
            'display_dimensions': dimensions,
            'iosurface_getters': {
                'status': 'confirmed_addresses',
                'detail': 'seven ldr/ret getters validated; virtual owner/invocation unknown',
                'owner_virtual': 'unknown',
                'invocation': 'unknown',
            },
            'swap_request_queue': {'status': 'unknown', 'detail': 'not derived by this version'},
            'user_client': {'status': 'unknown', 'detail': 'not derived by this version'},
            'prototypes': {
                'status': 'structural_header_emitted',
                'detail': '358 slots declared; unclassified slots are opaque and never called',
            },
        },
        'header_emitted': True,
        'bindings_emitted': True,
        'runtime_qualified': False,
        'images_modified': False,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if cpu_contract is not None:
        report['contracts']['cpu_present'] = cpu_contract
        report['contracts']['swap_request_queue'] = {
            'status': 'static_qualified_subset',
            'detail': 'Selected CPU fields and original activation/completion; execution unqualified'}
    (args.output_dir / 'OriginalLegacyFramebufferABI.h').write_text(
        generate_header(), encoding='utf-8')
    (args.output_dir / 'display-abi.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    asm = ['.text']
    for name, va in bindings.items():
        asm += [f'.globl {name}', f'.set {name}, {va:#x}']
    (args.output_dir / 'original-legacy-bindings.S').write_text(
        '\n'.join(asm) + '\n', encoding='utf-8')
    print(json.dumps({
        'legacy_ctor': hex(legacy_ctor), 'legacy_vptr': hex(legacy_vptr),
        'service_vptr': hex(service_vptr), 'base_vptr': hex(base_vptr),
        'metaclass': hex(metaclass_ctor), 'gMetaClass': hex(class_object),
        'iosurface_getters': len(iosurface_getters),
        'bindings': report['bindings'], 'contracts': report['contracts'],
    }, indent=2))


if __name__ == '__main__':
    main()
