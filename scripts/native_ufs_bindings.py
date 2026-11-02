#!/usr/bin/env python3
"""Bind nabu UFS to ordinary ARM64 21H16 IOStorageFamily at slide -0x1360000."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

SLIDE = -0x1360000
VTABLE = 0xfffffff0059644c0
META = 0xfffffff0067751d0
CONSTRUCTOR = 0xfffffff0046ced98
DESTRUCTOR = 0xfffffff0046cedb8
SLOTS = {
    21: ("__ZN20IOBlockStorageDevice4initEP12OSDictionary", 0xfffffff0046cee30),
    33: ("__ZNK20IOBlockStorageDevice11getPropertyEPK8OSSymbol", 0xfffffff0046cee88),
    44: ("__ZN20IOBlockStorageDevice13setPropertiesEP8OSObject", 0xfffffff0046cef38),
    185: ("__ZN20IOBlockStorageDevice11requestIdleEv", 0xfffffff0046cf050),
    186: ("__ZN20IOBlockStorageDevice7doUnmapEP26IOBlockStorageDeviceExtentjj", 0xfffffff0046cf05c),
    187: ("__ZN20IOBlockStorageDevice13doSetPriorityEP26IOBlockStorageDeviceExtentjh", 0xfffffff0046cf068),
    189: ("__ZN20IOBlockStorageDevice20doGetProvisionStatusEyyPjP35IOBlockStorageProvisionDeviceExtenty", 0xfffffff0046cf08c),
}
BINDINGS = dict(SLOTS.values()) | {
    "__ZTV20IOBlockStorageDevice": VTABLE,
    "__ZN20IOBlockStorageDevice10gMetaClassE": META,
    "__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass": CONSTRUCTOR,
    "__ZN20IOBlockStorageDeviceD2Ev": DESTRUCTOR,
}


class MachO:
    """Read symbol/section relocations without executing or modifying an input."""
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        d = self.data
        magic, cpu, subtype, self.kind, count, size = struct.unpack_from('<6I', d)
        if (magic, cpu, subtype) != (0xfeedfacf, 0x100000c, 0):
            raise ValueError('Expected ordinary ARM64 Mach-O')
        self.sections, self.symbols, self.segments = [], [], []
        at = 32
        for _ in range(count):
            cmd, length = struct.unpack_from('<II', d, at)
            if length < 8 or at + length > 32 + size:
                raise ValueError('Invalid load command')
            if cmd == 0x19:
                va, extent, off, backed = struct.unpack_from('<4Q', d, at + 24)
                self.segments.append((va, extent, off, backed))
                nsects = struct.unpack_from('<I', d, at + 64)[0]
                for i in range(nsects):
                    s = at + 72 + 80 * i
                    address, nbytes, fileoff, _, reloff, nreloc = struct.unpack_from('<QQ4I', d, s + 32)
                    self.sections.append((address, nbytes, fileoff, reloff, nreloc))
            elif cmd == 2:
                symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', d, at + 8)
                for i in range(nsyms):
                    ix, kind, sect, desc, value = struct.unpack_from('<IBBHQ', d, symoff + i * 16)
                    end = d.index(b'\0', stroff + ix, stroff + strsize)
                    self.symbols.append((d[stroff + ix:end].decode(), value, kind))
            at += length
        self.names = {name: value for name, value, kind in self.symbols
                      if not kind & 0xe0 and kind & 0xe}

    def read(self, address, length):
        for va, _, off, backed in self.segments:
            if va <= address and address + length <= va + backed:
                return self.data[off + address - va:off + address - va + length]
        raise ValueError('Unbacked address %#x' % address)

    def relocations(self, address):
        section = next(s for s in self.sections if s[0] <= address < s[0] + s[1])
        result = {}
        for i in range(section[4]):
            offset, word = struct.unpack_from('<II', self.data, section[3] + 8 * i)
            if word >> 27 & 1 and word >> 28 == 0 and word >> 25 & 3 == 3:
                result[section[0] + offset] = self.symbols[word & 0xffffff][0]
        return result


def qualify_object(obj):
    if obj.kind != 1:
        raise ValueError('Expected a relocatable driver object')
    vtable = obj.names['__ZTV14NativeUfsBlock']
    reloc = obj.relocations(vtable)
    methods = [reloc.get(vtable + 16 + 8 * i) for i in range(190)]
    if not all(methods) or vtable + 16 + 190 * 8 in reloc or '___cxa_pure_virtual' in methods:
        raise ValueError('Expected a concrete 190-slot block subclass')
    for index, (name, _) in SLOTS.items():
        if methods[index] != name:
            raise ValueError('Storage ABI mismatch at slot %d' % index)
    imports = {name for name, _, kind in obj.symbols if kind == 1 and 'IOBlockStorageDevice' in name}
    if imports != set(BINDINGS):
        raise ValueError('Unexpected storage imports: %s' % sorted(imports ^ set(BINDINGS)))
    return methods


def check_candidate(obj, candidate, plan):
    if plan['slide'] != SLIDE:
        raise ValueError('Storage bindings require slide -0x1360000')
    extents = {e['segment']: e for e in plan['extents']
               if e['module'] == 'com.apple.iokit.IOStorageFamily'}
    expected = {'__TEXT_EXEC': (0xfffffff0046cc000, 0x14358),
                '__DATA_CONST': (0xfffffff005963200, 0x5c10),
                '__DATA': (0xfffffff006775000, 0x3b1)}
    for name, (va, size) in expected.items():
        if (extents[name]['va'], extents[name]['size']) != (va, size):
            raise ValueError('Unexpected 21H16 storage extent ' + name)
    checked, own = 0, 0
    for index, name in enumerate(qualify_object(obj)):
        target = struct.unpack('<Q', candidate.read(VTABLE + 16 + index * 8, 8))[0]
        if name.startswith(('__ZN14NativeUfsBlock', '__ZNK14NativeUfsBlock')):
            own += 1
            continue
        wanted = BINDINGS.get(name, candidate.names.get(name))
        if wanted is None or target != wanted:
            raise ValueError('Original/native dispatch mismatch at slot %d: %s' % (index, name))
        checked += 1
    # These are the real base constructor and base destructor, not abstract D0/D1 traps.
    words = struct.unpack('<8I', candidate.read(CONSTRUCTOR, 32))
    if words[:2] != (0xa9bf7bfd, 0x910003fd) or words[5:] != (0xf9000008, 0xa8c17bfd, 0xd65f03c0):
        raise ValueError('Original base constructor shape changed')
    if struct.unpack('<I', candidate.read(DESTRUCTOR, 4))[0] & 0xfc000000 != 0x14000000:
        raise ValueError('Original base destructor is not the forwarding D2')
    getter = struct.unpack('<3I', candidate.read(0xfffffff0046cedc4, 12))
    a, add, ret = getter
    imm = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
    if imm & 0x100000:
        imm -= 0x200000
    if ret != 0xd65f03c0 or (0xfffffff0046cedc4 & ~4095) + imm * 4096 + (add >> 10 & 4095) != META:
        raise ValueError('Original storage metaclass changed')
    return {'virtual_slots': 190, 'inherited_slots_checked': checked,
            'concrete_overrides': own, 'bindings': {n: hex(v) for n, v in BINDINGS.items()},
            'slide': SLIDE, 'hardware_tested': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--object', type=Path, required=True)
    p.add_argument('--candidate', type=Path)
    p.add_argument('--prelink-report', type=Path)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    obj = MachO(args.object)
    qualify_object(obj)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.candidate:
        report = check_candidate(obj, MachO(args.candidate), json.loads(args.prelink_report.read_text()))
        (args.output_dir / 'candidate-bindings.json').write_text(json.dumps(report, indent=2) + '\n')
    else:
        assembly = args.output_dir / 'original-bindings.S'
        assembly.write_text(''.join('.globl %s\n.set %s, %#x\n' % (n, n, v)
                                    for n, v in sorted(BINDINGS.items())))
        output = args.output_dir / 'original-bindings.o'
        subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c', str(assembly), '-o', str(output)], check=True)
        archive = args.output_dir / 'libNativeUfs.a'
        if archive.exists():
            raise ValueError('Refuse an existing driver archive')
        subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(args.object), str(output)], check=True)
        report = {'archive': str(archive), 'slide': SLIDE,
                  'bindings': {n: hex(v) for n, v in BINDINGS.items()}, 'hardware_tested': False}
        (args.output_dir / 'bindings.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
