#!/usr/bin/env python3
"""Combine original TrustCache_t modules for DarwinBoot/XNU."""
import argparse
from pathlib import Path
import struct


def validate_module(raw):
    if len(raw) < 24:
        raise ValueError("truncated trust cache module")
    version, = struct.unpack_from("<I", raw)
    count, = struct.unpack_from("<I", raw, 20)
    if version != 2 or len(raw) != 24 + count * 24:
        raise ValueError("unsupported trust cache module layout")
    previous = None
    for offset in range(24, len(raw), 24):
        entry = raw[offset:offset + 20]
        hash_type = raw[offset + 20]
        if hash_type not in (1, 2, 3, 4) or (previous is not None and entry <= previous):
            raise ValueError("invalid or unsorted trust cache entry")
        previous = entry
    return count


def build(modules):
    if not 1 <= len(modules) <= 128:
        raise ValueError("DarwinBoot supports 1 through 128 trust cache modules")
    offsets = []
    offset = 4 + 4 * len(modules)
    for raw in modules:
        validate_module(raw)
        offsets.append(offset)
        offset += len(raw)
    return struct.pack(f"<{1 + len(modules)}I", len(modules), *offsets) + b"".join(modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modules", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"refuse to overwrite {args.output}")
    args.output.write_bytes(build([path.read_bytes() for path in args.modules]))
    print(f"Wrote {args.output} from {len(args.modules)} original trust cache module(s)")


if __name__ == "__main__":
    main()
