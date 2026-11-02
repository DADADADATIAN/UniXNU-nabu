"""Build the nabu IOWatchdog publisher against the original 21H16 AppleARMWatchdogTimer.

The original IOWatchdog base (user-client, boot-arg parsing, userspace
monitoring) is bound by address; only the three SoC hooks are supplied by
NabuWatchdog.cpp and they perform no MMIO. Every bound address is checked
against the selected original kernelcache before any object is produced.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

SLIDE = -0x1360000
IOWATCHDOG_VTABLE = 0xfffffff006f1bc28
IOWATCHDOG_META = 0xfffffff007bd6828
IOWATCHDOG_CTOR = 0xfffffff00667c400
IOWATCHDOG_DTOR = 0xfffffff00667c420
IOWATCHDOG_STOP = 0xfffffff00667cb6c
IOWATCHDOG_NEW_USER_CLIENT = 0xfffffff00667ce14
IOWATCHDOG_INIT = 0xfffffff00667c498
CXA_PURE_VIRTUAL = 0xfffffff007773874
SLOTS = 171
SOC_SLOTS = (168, 169, 170)
# First 16 original bytes of each bound function (21H16 static analysis).
EXPECTED_CODE = {
    IOWATCHDOG_CTOR: 'fd7bbfa9fd03009152060094e84400f0',
    IOWATCHDOG_INIT: 'ff0302d1f85f04a9f65705a9f44f06a9',
    IOWATCHDOG_STOP: 'f44fbea9fd7b01a9fd430091f30301aa',
    IOWATCHDOG_NEW_USER_CLIENT: 'f85fbca9f65701a9f44f02a9fd7b03a9',
}


def abi_header():
    return ('// SPDX-License-Identifier: BSD-2-Clause-Patent\n'
            '// Generated from the 21H16 original IOWatchdog (AppleARMWatchdogTimer kext).\n'
            '// Opaque storage for the exact original base; no private field access.\n'
            '#pragma once\n#include <IOKit/IOService.h>\n'
            'class IOWatchdog : public IOService {\n'
            '  OSDeclareAbstractStructors(IOWatchdog)\n'
            '  unsigned char originalPrivate[0xf8 - sizeof(IOService)];\npublic:\n'
            '  void stop(IOService *) override;\n'
            '  // Slot 140: the five-argument overload with the client properties.\n'
            '  IOReturn newUserClient(task_t, void *, UInt32, OSDictionary *, IOUserClient **) override;\n'
            '  // Slots 168..170: original pure-virtual SoC watchdog enable/disable/pet.\n'
            '  virtual void socWatchdogEnable() = 0;\n'
            '  virtual void socWatchdogDisable() = 0;\n'
            '  virtual void socWatchdogPet() = 0;\n'
            '};\n'
            'static_assert(sizeof(IOWatchdog) == 0xf8, "Original IOWatchdog instance extent");\n'
            '// Original non-virtual base initializer called by AppleARMWatchdogTimer::start.\n'
            'extern "C" bool original_iowatchdog_init(IOWatchdog *, IOService *, void *, uint32_t);\n')


def original_bindings(data, native_prelink):
    image = native_prelink.macho(data)
    segments = image['segments']

    def read(address, size):
        at = native_prelink.backed_offset(segments, address, size, len(data))
        return data[at:at + size]

    for address, expected in EXPECTED_CODE.items():
        if read(address, 16).hex() != expected:
            raise ValueError(f'Original IOWatchdog code differs at {address:#x}')
    slots = struct.unpack('<%dQ' % SLOTS, read(IOWATCHDOG_VTABLE, SLOTS * 8))
    if read(IOWATCHDOG_VTABLE + SLOTS * 8, 8) != bytes(8):
        raise ValueError('Original IOWatchdog vtable does not end after 171 slots')
    if slots[87] != IOWATCHDOG_STOP or slots[140] != IOWATCHDOG_NEW_USER_CLIENT:
        raise ValueError('Original IOWatchdog stop/newUserClient slots moved')
    if any(slots[slot] != CXA_PURE_VIRTUAL for slot in SOC_SLOTS):
        raise ValueError('Original IOWatchdog SoC hooks are not pure virtual')
    return {
        '__ZN10IOWatchdogC2EPK11OSMetaClass': IOWATCHDOG_CTOR + SLIDE,
        '__ZN10IOWatchdogD2Ev': IOWATCHDOG_DTOR + SLIDE,
        '__ZN10IOWatchdog10gMetaClassE': IOWATCHDOG_META + SLIDE,
        '__ZN10IOWatchdog4stopEP9IOService': IOWATCHDOG_STOP + SLIDE,
        '__ZN10IOWatchdog13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient':
            IOWATCHDOG_NEW_USER_CLIENT + SLIDE,
        '_original_iowatchdog_init': IOWATCHDOG_INIT + SLIDE,
    }


def binding_assembly(bindings):
    text = '.text\n'
    for name, target in bindings.items():
        text += f'.globl {name}\n.set {name}, {target:#x}\n'
    return text


def build(root, record, out, compile_command, original_kernel):
    sys.path.insert(0, str(root / 'kits/NativePrelink'))
    import native_prelink
    out.mkdir(parents=True, exist_ok=False)
    (out / 'OriginalIOWatchdogABI.h').write_text(abi_header(), encoding='utf-8')
    bindings = original_bindings(original_kernel.read_bytes(), native_prelink)
    assembly = out / 'original-bindings.S'
    assembly.write_text(binding_assembly(bindings), encoding='utf-8')
    source = Path(os.environ['UNIXNU_DEVICE']) / 'platform' / 'NabuWatchdog.cpp'
    obj = out / 'NabuWatchdog.o'
    command = compile_command(record, source, obj)
    command += ['-I', str(out), '-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    subprocess.run(command, cwd=record['directory'], check=True)
    # Register the subclass only after the original parent kext has started.
    late = out / 'NabuWatchdog.late.o'
    subprocess.run(['llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_NabuWatchdog.cpp', str(obj), str(late)], check=True)
    alias_obj = out / 'original-bindings.o'
    subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                    str(assembly), '-o', str(alias_obj)], check=True)
    (out / 'bindings.json').write_text(json.dumps({
        'original_build': '21H16', 'slide': SLIDE,
        'original_kernel': str(original_kernel),
        'original_kernel_sha256': hashlib.sha256(original_kernel.read_bytes()).hexdigest(),
        'bindings': {name: hex(address) for name, address in bindings.items()},
        'soc_slots': list(SOC_SLOTS), 'soc_hooks_mmio': False,
        'publication_requires_boot_arg': 'wdt=-1',
        'hardware_watchdog_implemented': False, 'runtime_qualified': False,
        'source': 'NabuWatchdog.cpp',
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    }, indent=2) + '\n', encoding='utf-8')
    return [late, alias_obj]
