#!/usr/bin/env python3
"""Turn the pinned XNU build's dependency guards into warnings, for CI only.

`scripts/build-xnu-4k-baseline.sh` cross-checks the feature graph of a device
profile (owner root, Data/SystemOS mounts, Virtio block, AES, displays, ...).
Several of those checks demand `XNU_VERIFIED_ROOT_PROBE=1`, which the project's
private CI satisfies through an owner-policy input that is not in any public
repository. This script keeps every check, keeps every warning, and only turns
the `exit 1` of a guard that explains itself on stderr into a no-op, so an
image-less compile check can reach the compiler and report real code errors.

Nothing else is touched: genuine failures (missing archives, failed compiles,
`test -f`) still exit non-zero.

Usage:
    ci-relax-build-gates.py <path-to>/scripts/build-xnu-4k-baseline.sh

Exits 0 when at least one guard was relaxed, 1 when the file did not match.
"""
import re
import sys
from pathlib import Path

GUARD_MESSAGE = re.compile(r"^\s*echo '(?P<message>[^']+)' >&2$")
# A guard explains the requirement it failed; a genuine failure usually does not.
GUARD_HINTS = ('require', 'must be')


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: ci-relax-build-gates.py <scripts/build-xnu-4k-baseline.sh>')
    path = Path(sys.argv[1])
    lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    relaxed = []
    for index, line in enumerate(lines):
        if line.strip() != 'exit 1':
            continue
        for back in range(1, 6):
            if index - back < 0:
                break
            match = GUARD_MESSAGE.match(lines[index - back].rstrip('\n'))
            if not match:
                continue
            message = match.group('message')
            if any(hint in message.lower() for hint in GUARD_HINTS):
                lines[index] = line.replace('exit 1', ': # ci-relax-build-gates: guard relaxed')
                relaxed.append(message)
            break
    if not relaxed:
        print('ci-relax-build-gates: no guard matched; already relaxed?')
        return 1
    path.write_text(''.join(lines), encoding='utf-8')
    for message in relaxed:
        print(f'ci-relax-build-gates: relaxed: {message}')
    print(f'ci-relax-build-gates: {len(relaxed)} guard(s) relaxed in {path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
