"""Build the QEMU AON backend against the selected original 21H16 PMGR."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

SLIDE = -0x1360000
PMGR_VTABLE = 0xfffffff006cf1c98
PMGR_META = 0xfffffff007ad7350
PMGR_CTOR = 0xfffffff005aac03c
PMGR_DTOR = 0xfffffff005aac19c
NUB_FACTORY = 0xfffffff005ade568


def abi_header():
    text = ('// Generated slot declarations; opaque methods are never called by this source.\n'
            '#pragma once\n#include <IOKit/IOPMGR.h>\n'
            'class ApplePMGR : public IOPMGR {\n'
            '  OSDeclareAbstractStructors(ApplePMGR)\n'
            '  unsigned char originalPrivate[0x4b8a8 - sizeof(IOPMGR)];\npublic:\n')
    for slot in range(177, 340):
        if slot == 320:
            text += '  virtual uint32_t readAon();\n'
        elif slot == 321:
            text += '  virtual void writeAon(uint64_t);\n'
        else:
            text += f'  virtual void opaque{slot}();\n'
    return text + '};\nstatic_assert(sizeof(ApplePMGR) == 0x4b8a8, "Original parent storage");\n'


def original_bindings(data, native_prelink):
    image = native_prelink.macho(data)
    segments = image['segments']

    def pointer(address):
        at = native_prelink.backed_offset(segments, address, 8, len(data))
        return struct.unpack_from('<Q', data, at)[0]

    bindings = {
        '__ZN9ApplePMGRC2EPK11OSMetaClass': PMGR_CTOR + SLIDE,
        '__ZN9ApplePMGRD2Ev': PMGR_DTOR + SLIDE,
        '__ZN9ApplePMGR10gMetaClassE': PMGR_META + SLIDE,
        '_qemu_original_pmgr_nub_create': NUB_FACTORY + SLIDE,
    }
    for slot in range(177, 340):
        if slot in (320, 321):
            continue
        name = f'opaque{slot}'
        target = pointer(PMGR_VTABLE + slot * 8)
        # Original abstract entries belong to XNU, not the relocated kext.
        bindings[f'__ZN9ApplePMGR{len(name)}{name}Ev'] = (
            '___cxa_pure_virtual' if target == 0xfffffff007773874 else target + SLIDE)
    return bindings


def binding_assembly(bindings):
    text = '.text\n'
    for name, target in bindings.items():
        text += f'.globl {name}\n'
        if isinstance(target, str):
            text += f'.p2align 2\n{name}:\n  b {target}\n'
        else:
            text += f'.set {name}, {target:#x}\n'
    return text


def build(root, record, out, compile_command, original_kernel,
          source_name='QemuBootPMGR.cpp', prefix='QemuBootPMGR',
          aon_storage='volatile QEMU boot-session state'):
    sys.path.insert(0, str(root / 'kits/NativePrelink'))
    import native_prelink
    out.mkdir(parents=True, exist_ok=False)
    (out / 'OriginalPMGRABI.h').write_text(abi_header(), encoding='utf-8')
    bindings = original_bindings(original_kernel.read_bytes(), native_prelink)
    assembly = out / 'original-bindings.S'
    assembly.write_text(binding_assembly(bindings), encoding='utf-8')
    source = Path(os.environ['UNIXNU_DEVICE']) / 'platform' / source_name
    obj = out / (prefix + '.o')
    command = compile_command(record, source, obj)
    command += ['-I', str(out), '-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    subprocess.run(command, cwd=record['directory'], check=True)
    # Register the subclass only after the original parent kext has started.
    late = out / (prefix + '.late.o')
    subprocess.run(['llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                    '--globalize-symbol=__GLOBAL__sub_I_' + source_name, str(obj), str(late)], check=True)
    alias_obj = out / 'original-bindings.o'
    subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                    str(assembly), '-o', str(alias_obj)], check=True)
    (out / 'bindings.json').write_text(json.dumps({
        'original_build': '21H16', 'slide': SLIDE,
        'original_kernel': str(original_kernel),
        'bindings': {name: hex(address) if isinstance(address, int) else address
                     for name, address in bindings.items()},
        'aon_slots': [320, 321], 'aon_storage': aon_storage,
        'hardware_power_implemented': False, 'runtime_qualified': False,
        'source': source_name,
    }, indent=2) + '\n', encoding='utf-8')
    return [late, alias_obj]
