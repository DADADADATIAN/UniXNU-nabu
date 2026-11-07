#!/usr/bin/env python3
"""Relax the pinned XNU build gates for a CI-only kernel compile check.

Mirrors exactly the build-script rewrites that source-ci/prepare_source.py
applies for the nabu owner/Data/UFS profiles, without needing the private
owner-policy, display-reference or IPSW-small inputs. Only gate conditions are
rewritten; no kernel source is touched.

Usage:
    ci-relax-build-gates.py <path-to>/scripts/build-xnu-4k-baseline.sh

Exits 0 when anchors were rewritten, 1 when nothing matched (already relaxed or
the pinned script text changed).
"""
import sys
from pathlib import Path

CRYPTO_GATE = ('if [ "$CRYPTO_BOOTSTRAP_MODE" != prelinked ] '
               '|| [ "${XNU_SOURCE_CORECRYPTO14:-0}" != 1 ]; then')

REPLACEMENTS = [
    ('if [ "${XNU_NATIVE_AES:-0}" != 1 ]; then\n'
     "    echo 'NativeVirtioBlock currently requires the qualified "
     "NativeAES/original-storage prelink baseline' >&2",
     CRYPTO_GATE + '\n'
     "    echo 'NativeVirtioBlock requires the original crypto/storage prelink closure' >&2"),
    ('if [ "${XNU_NATIVE_AES:-0}" != 1 ]; then\n'
     "    echo 'NativeRamBlock requires the qualified original "
     "storage/AES prelink closure' >&2",
     CRYPTO_GATE + '\n'
     "    echo 'NativeRamBlock requires the original crypto/storage prelink closure' >&2"),
    ('if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "$OWNER_ROOT_PROBE" != 1 ]; then',
     'if [ "$OWNER_ROOT_AUDIT" = 1 ] '
     '&& [ "${XNU_NATIVE_VIRTIO_BLOCK:-0}" != 1 ]; then'),
    ('if [ "$OWNER_ROOT_PROBE" = 1 ] && {',
     'if { [ "$OWNER_ROOT_PROBE" = 1 ] '
     '|| [ "${XNU_OWNER_ROOT_AUDIT:-0}" = 1 ]; } && {'),
    ('  if [ "$OWNER_ROOT_PROBE" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE=',
     '  if [ "$OWNER_ROOT_PROBE" = 1 ] || [ "$OWNER_ROOT_AUDIT" = 1 ]; then\n'
     '    VERIFIED_ROOT_ARCHIVE='),
    ('  "$OWNER_ROOT_PROBE" "${XNU_VERIFIED_ROOT_ARCHIVE:',
     '  "$((OWNER_ROOT_PROBE | OWNER_ROOT_AUDIT))" "${XNU_VERIFIED_ROOT_ARCHIVE:'),
]


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: ci-relax-build-gates.py <scripts/build-xnu-4k-baseline.sh>')
    path = Path(sys.argv[1])
    text = path.read_text(encoding='utf-8')
    applied = 0
    for old, new in REPLACEMENTS:
        count = text.count(old)
        if count == 0:
            print('ci-relax-build-gates: anchor missing (already relaxed?): '
                  + old.splitlines()[0].strip())
            continue
        text = text.replace(old, new)
        applied += count
        print(f'ci-relax-build-gates: rewritten x{count}: '
              + old.splitlines()[0].strip())
    path.write_text(text, encoding='utf-8')
    print(f'ci-relax-build-gates: {applied} rewrite(s) in {path}')
    return 0 if applied else 1


if __name__ == '__main__':
    sys.exit(main())
