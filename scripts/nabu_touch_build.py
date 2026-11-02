"""Build the nabu NT36523 touch digitizer against the original 21H16 IOHIDDevice.

Follows UniXNU drivers/ShengHidInput (build-sheng-hid-input.py): the original
IOHIDFamily device base, parser and event driver stay unchanged; only the
touch-only subclass is owned. Every bound address is checked against the
selected original kernelcache before any object is produced, and the compiled
vtable may override only the qualified slots.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

SLIDE = -0x1360000
IOHIDDEVICE_VTABLE = 0xfffffff006d6c740      # address point; __ZTV is 0x10 lower
IOHIDDEVICE_META = 0xfffffff007b22be0
IOHIDDEVICE_CTOR = 0xfffffff005d394f8
IOHIDDEVICE_DTOR = 0xfffffff005d39518
IOHIDDEVICE_HANDLE_START = 0xfffffff005d3c3a0
IOHIDDEVICE_HANDLE_REPORT = 0xfffffff005d3d0c4
CXA_PURE_VIRTUAL = 0xfffffff007773874
SLOTS = 207
IOSERVICE_SLOTS = 168
ORIGINAL_OVERRIDES = [0, 1, 7, 12, 14, 21, 23, 76, 81, 82, 86, 87, 91, 92, 93, 101, 132, 140]
OWNED_SLOTS = [0, 1, 7, 14, 86, 87, 111, 171, 173, 180]
CLASS = 'NabuTouchHid'


def abi_header():
    text = ('// SPDX-License-Identifier: BSD-2-Clause-Patent\n'
            '// Generated from the 21H16 original IOHIDDevice (IOHIDFamily-2031.120.4).\n'
            '// Opaque storage for the exact original base; no private field access.\n'
            '#pragma once\n#include <IOKit/IOService.h>\n#include <IOKit/IOMemoryDescriptor.h>\n'
            'class IOHIDDevice : public IOService {\n'
            ' OSDeclareAbstractStructors(IOHIDDevice)\n'
            ' unsigned char originalPrivate[0xd0-sizeof(IOService)];\npublic:\n'
            ' using IOService::setProperty;\n'
            ' IOReturn Dispatch(IORPC) override;\n void free() override;\n'
            ' bool init(OSDictionary *properties=nullptr) override;\n'
            ' bool setProperty(const OSSymbol *,OSObject *) override;\n'
            ' bool willTerminate(IOService *,IOOptionBits) override;\n'
            ' IOReturn configureReport(IOReportChannelList *,IOReportConfigureAction,void *,void *) override;\n'
            ' IOReturn updateReport(IOReportChannelList *,IOReportUpdateAction,void *,void *) override;\n'
            ' bool start(IOService *) override;\n void stop(IOService *) override;\n'
            ' bool handleOpen(IOService *,IOOptionBits,void *) override;\n'
            ' void handleClose(IOService *,IOOptionBits) override;\n'
            ' bool handleIsOpen(const IOService *) const override;\n'
            ' bool matchPropertyTable(OSDictionary *,SInt32 *) override;\n'
            ' IOReturn message(UInt32,IOService *,void *) override;\n'
            ' IOReturn newUserClient(task_t,void *,UInt32,OSDictionary *,IOUserClient **) override;\n')
    for slot in range(IOSERVICE_SLOTS, SLOTS):
        if slot == 171:
            text += ' virtual OSString *newTransportString() const;\n'
        elif slot == 173:
            text += ' virtual OSString *newProductString() const;\n'
        elif slot == 180:
            text += ' virtual IOReturn newReportDescriptor(IOMemoryDescriptor **) const=0;\n'
        elif slot == 181:
            text += ' virtual IOReturn handleReport(IOMemoryDescriptor *,unsigned,IOOptionBits);\n'
        else:
            text += (f' virtual __attribute__((deprecated("Unqualified prototype: never call from source")))'
                     f' void opaque{slot}();\n')
    text += '};\nstatic_assert(sizeof(IOHIDDevice)==0xd0,"Original device instance size");\n'
    return text


def original_methods(data, native_prelink):
    image = native_prelink.macho(data)

    def read(address, size):
        at = native_prelink.backed_offset(image['segments'], address, size, len(data))
        return data[at:at + size]

    methods = struct.unpack('<%dQ' % SLOTS, read(IOHIDDEVICE_VTABLE, SLOTS * 8))
    if read(IOHIDDEVICE_VTABLE + SLOTS * 8, 24) != bytes(24):
        raise ValueError('Original IOHIDDevice vtable does not end after 207 slots')
    if [i for i, a in enumerate(methods) if a == CXA_PURE_VIRTUAL] != [180] or not all(methods):
        raise ValueError('Original IOHIDDevice is not the 207-slot device with pure slot 180')
    if methods[168] != IOHIDDEVICE_HANDLE_START or methods[181] != IOHIDDEVICE_HANDLE_REPORT:
        raise ValueError('Original IOHIDDevice handleStart/handleReport slots moved')
    # C2: frame setup, IOService C2 call, then the IOHIDDevice vptr store.
    if read(IOHIDDEVICE_CTOR, 8).hex() != 'fd7bbfa9fd030091':
        raise ValueError('Original IOHIDDevice constructor differs')
    return methods


def object_vtable(native_prelink, raw, name):
    image = native_prelink.macho(raw)
    table = next(p for c, p, _ in image['commands'] if c == 2)
    symoff, count, stroff, _ = struct.unpack_from('<4I', raw, table + 8)
    symbols = []
    for index in range(count):
        strx, kind, _, _, va = struct.unpack_from('<IBBHQ', raw, symoff + index * 16)
        symbols.append((raw[stroff + strx:raw.index(b'\0', stroff + strx)].decode(), va, kind))
    vtable = next(va for sym, va, _ in symbols if sym == name)
    relocations = {}
    for segment in image['segments']:
        for section in segment['sections']:
            if section['va'] <= vtable < section['va'] + section['size']:
                ro, rc = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
                for index in range(rc):
                    offset, bits = struct.unpack_from('<2I', raw, ro + index * 8)
                    if bits >> 27 & 1 and bits >> 28 == 0 and bits >> 25 & 3 == 3:
                        relocations[section['va'] + offset] = symbols[bits & 0xffffff][0]
    compiled = [relocations.get(vtable + 16 + slot * 8) for slot in range(SLOTS)]
    if not all(compiled) or vtable + 16 + SLOTS * 8 in relocations:
        raise ValueError('Compiled touch vtable is not exactly 207 slots')
    return symbols, compiled


def build(root, record, out, compile_command, original_kernel):
    sys.path.insert(0, str(root / 'kits/NativePrelink'))
    import native_prelink
    out.mkdir(parents=True, exist_ok=False)
    (out / 'OriginalHidDeviceABI.h').write_text(abi_header(), encoding='utf-8')
    kernel = original_kernel.read_bytes()
    methods = original_methods(kernel, native_prelink)
    source = Path(os.environ['UNIXNU_DEVICE']) / 'platform' / 'NabuTouch.cpp'
    obj = out / 'NabuTouch.o'
    command = compile_command(record, source, obj)
    command += ['-I', str(out), '-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    raw = obj.read_bytes()
    symbols, compiled = object_vtable(native_prelink, raw, f'__ZTV{len(CLASS)}{CLASS}')
    own = (f'__ZN{len(CLASS)}{CLASS}', f'__ZNK{len(CLASS)}{CLASS}')
    bindings = {'__ZN11IOHIDDeviceC2EPK11OSMetaClass': IOHIDDEVICE_CTOR + SLIDE,
                '__ZN11IOHIDDeviceD2Ev': IOHIDDEVICE_DTOR + SLIDE,
                '__ZN11IOHIDDevice10gMetaClassE': IOHIDDEVICE_META + SLIDE,
                '__ZTV11IOHIDDevice': IOHIDDEVICE_VTABLE - 16 + SLIDE}
    owned = []
    for slot, name in enumerate(compiled):
        if name.startswith(own):
            owned.append(slot)
        elif '11IOHIDDevice' in name:
            bindings[name] = methods[slot] + SLIDE
        elif slot >= IOSERVICE_SLOTS or slot in ORIGINAL_OVERRIDES:
            raise ValueError(f'Slot {slot} must bind the original IOHIDDevice, got {name}')
    if owned != OWNED_SLOTS:
        raise ValueError(f'Only qualified HID methods may be overridden, got {owned}')
    undefined = {name for name, _, kind in symbols if kind == 1 and '11IOHIDDevice' in name}
    if not undefined <= set(bindings):
        raise ValueError('Unbound original HID imports: ' + ', '.join(sorted(undefined - set(bindings))))
    bindings = {name: address for name, address in bindings.items() if name in undefined}
    assembly = out / 'original-bindings.S'
    assembly.write_text('.text\n' + ''.join(f'.globl {n}\n.set {n}, {a:#x}\n'
                                            for n, a in sorted(bindings.items())), encoding='utf-8')
    # Register the subclass only after the original IOHIDFamily kext has started.
    late = out / 'NabuTouch.late.o'
    subprocess.run(['llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_NabuTouch.cpp', str(obj), str(late)], check=True)
    alias_obj = out / 'original-bindings.o'
    subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                    str(assembly), '-o', str(alias_obj)], check=True)
    (out / 'bindings.json').write_text(json.dumps({
        'original_build': '21H16', 'slide': SLIDE,
        'original_kernel': str(original_kernel),
        'original_kernel_sha256': hashlib.sha256(kernel).hexdigest(),
        'bindings': {name: hex(address) for name, address in sorted(bindings.items())},
        'owned_slots': owned, 'vtable_symbols': compiled,
        'publication_requires_boot_arg': 'nabu-touch=1',
        'firmware_source': 'ADT /nabu-touch (private, not in the build)',
        'runtime_qualified': False,
        'source': 'NabuTouch.cpp', 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    }, indent=2) + '\n', encoding='utf-8')
    return [late, alias_obj]
