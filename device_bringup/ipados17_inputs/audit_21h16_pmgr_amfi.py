#!/usr/bin/env python3
"""Audit the 21H16 (ipad7c) AMFI/ApplePMGR ABI constants for the nabu port.

Method validation: the same derivation runs on the 21H461 (ipad7) kernelcache and
every derived constant is compared against the values hardcoded by the upstream
UniXNU-sheng builder/audit (converted from candidate space to cache space with
the upstream slide -0x1000000). Only when the 21H461 column fully reproduces the
upstream constants is the 21H16 column accepted.

Static analysis of original Apple bytes only; no hardware, no QEMU, no boot claim.
"""
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'tools' / 'NativePrelink-3380d300'))
from native_prelink import macho, backed_offset, unserialize_xml

ROOT = Path(__file__).resolve().parent
INPUTS = {
    '21H16': ROOT / 'system-17.7-21H16-20261023' / 'decoded-complete' / 'kernelcache.macho',
    '21H461': ROOT / 'system-17.7.11-21H461-20261024' / 'kernelcache.21h461.macho',
}
# Upstream constants (candidate space, slide -0x1000000) -> cache space = +0x1000000.
UPSTREAM_21H461 = {
    'amfi_early_security_init': 0xfffffff005ab4ae0,
    'amfi_aon_update_sequence': 0xfffffff004aaeb40 + 0x1000000,
    'pmgr_c2_ctor': 0xfffffff0049f003c + 0x1000000,
    'pmgr_d2_dtor': 0xfffffff0049f019c + 0x1000000,
    'pmgr_ctor_vptr_store': 0xfffffff0049f0058 + 0x1000000,
    'pmgr_vtable': 0xfffffff005ce26d8 + 0x1000000,
    'pmgr_slot320': 0xfffffff004a20fbc + 0x1000000,
    'pmgr_slot321': 0xfffffff004a20fc4 + 0x1000000,
    'pmgr_meta_class': 0xfffffff006adf490 + 0x1000000,
    'pmgr_class_size': 0x4b8a8,
}
AMFI_SIGNPOST = b'kern_return_t _initializeAppleMobileFileIntegrity()\x00'
AMFI_PROLOGUE = (0xd10403ff, 0xa90c5ff8, 0xa90d57f6, 0xa90e4ff4, 0xa90f7bfd, 0x9103c3fd)
AON_UPDATE_MIDDLE = (0x321e0015, 0xaa1403e0, 0xaa1503e1)


class Cache:
    def __init__(self, path):
        self.data = path.read_bytes()
        self.meta = macho(self.data)
        info = next(s for s in self.meta['segments'] if s['name'] == '__PRELINK_INFO')
        at = backed_offset(self.meta['segments'], info['va'], info['filesize'], len(self.data))
        plist = unserialize_xml(self.data[at:at + info['filesize']])
        self.entries = {e['CFBundleIdentifier']: e for e in plist['_PrelinkInfoDictionary']}

    def read(self, va, size):
        at = backed_offset(self.meta['segments'], va, size, len(self.data))
        return self.data[at:at + size]

    def module(self, identifier):
        entry = self.entries[identifier]
        base = entry['_PrelinkExecutableLoadAddr']
        return entry, base, macho(self.data, backed_offset(self.meta['segments'], base, 32, len(self.data)))

    def module_read(self, sub, va, size):
        return self.read(va, size)

    def find_in_segment(self, sub, name, needle):
        seg = next(s for s in sub['segments'] if s['name'] == name)
        raw = self.read(seg['va'], seg['filesize'])
        at = raw.find(needle)
        return (seg['va'] + at) if at >= 0 else None

    def exec_words(self, sub):
        seg = next(s for s in sub['segments'] if s['name'] == '__TEXT_EXEC')
        raw = self.read(seg['va'], seg['filesize'])
        return seg, struct.unpack('<' + 'I' * (len(raw) // 4), raw)


def function_start_back(words, base_va, index):
    """Walk back to the word after the previous RET (the upstream functions begin with sub sp)."""
    i = index
    while i > 0 and words[i] != 0xd65f03c0:
        i -= 1
    return base_va + 4 * (i + 1)


def scan_xrefs(words, base_va, target):
    page, hits = {}, []
    for i, w in enumerate(words):
        va = base_va + 4 * i
        if (w & 0x9f000000) == 0x90000000:
            imm = ((w >> 5) & 0x7ffff) << 2 | ((w >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            page[w & 31] = (va & ~4095) + (imm << 12)
        elif (w & 0xffc00000) == 0x91000000:
            rn = (w >> 5) & 31
            if rn in page and page[rn] + ((w >> 10) & 4095) == target:
                hits.append(va)
    return hits


def scan_ctor_stores(words, base_va):
    """ADRP x8 / ADD x8 / STR x8,[x0] sequences; returns (store_va, vptr)."""
    page, found = {}, []
    for i in range(len(words) - 2):
        w0, w1, w2 = words[i], words[i + 1], words[i + 2]
        va0 = base_va + 4 * i
        if (w0 & 0x9f00001f) == 0x90000008 and (w1 & 0xffc003ff) == 0x91000108 and w2 == 0xf9000008:
            imm = ((w0 >> 5) & 0x7ffff) << 2 | ((w0 >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            vptr = (va0 & ~4095) + (imm << 12) + ((w1 >> 10) & 4095)
            found.append((va0, vptr))
    return found


def audit(cache, soc_pmgr_id, soc_class):
    out = {}
    # ---- AMFI ----
    entry, base, sub = cache.module('com.apple.driver.AppleMobileFileIntegrity')
    str_va = cache.find_in_segment(sub, '__TEXT', AMFI_SIGNPOST)
    seg, words = cache.exec_words(sub)
    xrefs = scan_xrefs(words, seg['va'], str_va)
    prologue_at = None
    if xrefs:
        limit = (xrefs[0] - seg['va']) // 4
        for i in range(limit, -1, -1):
            if list(words[i:i + len(AMFI_PROLOGUE)]) == list(AMFI_PROLOGUE):
                prologue_at = seg['va'] + 4 * i
                break
    out['amfi'] = {
        'load': base,
        'exec': seg['va'], 'exec_size': seg['filesize'],
        'initprot': seg['initprot'], 'maxprot': seg['maxprot'],
        'security_extension': entry.get('AppleSecurityExtension'),
        'signpost_string': str_va,
        'signpost_xrefs': [hex(x) for x in xrefs],
        'initialize_function': prologue_at,
    }
    aon = None
    for i in range(1, len(words) - 3):
        if list(words[i:i + 3]) == list(AON_UPDATE_MIDDLE):
            aon = seg['va'] + 4 * (i - 1)
            break
    out['amfi']['aon_update_sequence'] = aon

    # ---- ApplePMGR ----
    out['pmgr'] = audit_class(cache, 'com.apple.driver.ApplePMGR', b'ApplePMGR\x00')
    out['soc_pmgr'] = audit_class(cache, soc_pmgr_id, soc_class.encode() + b'\x00')
    return out


def audit_class(cache, identifier, name):
    entry, base, sub = cache.module(identifier)
    seg, words = cache.exec_words(sub)
    text = next(s for s in sub['segments'] if s['name'] == '__TEXT')
    traw = cache.read(text['va'], text['filesize'])
    names = []
    at = 0
    while True:
        at = traw.find(name, at)
        if at < 0:
            break
        names.append(text['va'] + at)
        at += 1
    result = {'load': base, 'exec': seg['va'], 'exec_size': seg['filesize'],
              'class_name_strings': [hex(n) for n in names]}
    stores = scan_ctor_stores(words, seg['va'])
    # The class vtable is the stored vptr whose slots 320/321 point back into this exec.
    vtable = slot320 = slot321 = None
    for _, vptr in stores:
        try:
            s320, s321 = struct.unpack('<2Q', cache.read(vptr + 320 * 8, 16))
        except Exception:
            continue
        if seg['va'] <= s320 < seg['va'] + seg['filesize'] and seg['va'] <= s321 < seg['va'] + seg['filesize']:
            vtable, slot320, slot321 = vptr, s320, s321
            break
    if vtable:
        result.update({
            'vtable': vtable,
            'slot320': slot320, 'slot320_words': [hex(w) for w in struct.unpack('<3I', cache.read(slot320, 12))],
            'slot321': slot321, 'slot321_words': [hex(w) for w in struct.unpack('<1I', cache.read(slot321, 4))],
        })
        # C2: the function containing the vptr store; entry skips B/BRK islands after the previous RET.
        store_pc = next(a for a, v in stores if v == vtable)
        i = (store_pc - seg['va']) // 4
        while i > 0 and words[i] != 0xd65f03c0:
            i -= 1
        i += 1
        while i < len(words) and ((words[i] & 0xfc000000) == 0x14000000 or words[i] == 0xd4200020):
            i += 1
        c2 = seg['va'] + 4 * i
        result['c2_ctor'] = c2
        # D2: the word right after C2's terminating RET (a branch island for an out-of-line dtor).
        j = i
        depth = 0
        while j < len(words):
            if words[j] == 0xd65f03c0:
                break
            j += 1
        result['d2_dtor'] = seg['va'] + 4 * (j + 1)
        # Class size: the static initializer passes className (ADRP+ADD into one of the
        # name strings) and a MOVZ/MOVK-built w3 to the OSMetaClass constructor.
        class_size = None
        for i in range(1, len(words) - 6):
            w0, w1 = words[i], words[i + 1]
            if (w0 & 0x9f000000) != 0x90000000 or (w1 & 0xffc00000) != 0x91000000:
                continue
            imm = ((w0 >> 5) & 0x7ffff) << 2 | ((w0 >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            target = ((seg['va'] + 4 * i) & ~4095) + (imm << 12) + ((w1 >> 10) & 4095)
            if target not in names:
                continue
            value, k = 0, i + 2
            while k < len(words) and k < i + 8:
                w = words[k]
                if (w & 0x7f800000) == 0x52800000:  # MOVZ
                    value = ((w >> 5) & 0xffff) << (16 * ((w >> 21) & 3))
                elif (w & 0x7f800000) == 0x72800000:  # MOVK
                    value |= ((w >> 5) & 0xffff) << (16 * ((w >> 21) & 3))
                elif (w & 0xfc000000) == 0x94000000:  # BL
                    k += 1
                    break
                k += 1
            if value:
                class_size = value
                result['class_size_site'] = seg['va'] + 4 * i
                break
        result['class_size'] = class_size
    return result


def hexify(node):
    if isinstance(node, dict):
        return {k: hexify(v) for k, v in node.items()}
    if isinstance(node, list):
        return [hexify(v) for v in node]
    if isinstance(node, int):
        return hex(node)
    return node


def main():
    results = {}
    results['21H16'] = audit(Cache(INPUTS['21H16']), 'com.apple.driver.AppleT8010PMGR', 'AppleT8010PMGR')
    results['21H461'] = audit(Cache(INPUTS['21H461']), 'com.apple.driver.AppleT8011PMGR', 'AppleT8011PMGR')

    v = results['21H461']
    validation = {
        'amfi_early_security_init': v['amfi']['initialize_function'] == UPSTREAM_21H461['amfi_early_security_init'],
        'amfi_aon_update_sequence': v['amfi']['aon_update_sequence'] == UPSTREAM_21H461['amfi_aon_update_sequence'],
        'pmgr_vtable': v['pmgr'].get('vtable') == UPSTREAM_21H461['pmgr_vtable'],
        'pmgr_slot320': v['pmgr'].get('slot320') == UPSTREAM_21H461['pmgr_slot320'],
        'pmgr_slot321': v['pmgr'].get('slot321') == UPSTREAM_21H461['pmgr_slot321'],
        'pmgr_c2_ctor': v['pmgr'].get('c2_ctor') == UPSTREAM_21H461['pmgr_c2_ctor'],
        'pmgr_d2_dtor': v['pmgr'].get('d2_dtor') == UPSTREAM_21H461['pmgr_d2_dtor'],
        'pmgr_class_size': v['pmgr'].get('class_size') == UPSTREAM_21H461['pmgr_class_size'],
    }
    results['validation_vs_upstream_21H461'] = validation
    ok = all(validation.values())
    print(json.dumps(hexify(results), indent=1)[:4000])
    print('VALIDATION', 'ALL MATCH' if ok else 'MISMATCH: ' + str([k for k, good in validation.items() if not good]))
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('pmgr-amfi-audit.json')
    out_path.write_text(json.dumps(hexify(results), indent=1) + '\n')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
