#!/usr/bin/env python3
"""Expand a 21H16 UDIF disk into a QEMU raw disk without mounting it."""
import argparse
from pathlib import Path
import plistlib
import struct

def convert(source, output):
    with source.open('rb') as image, output.open('xb') as disk:
        image.seek(-512, 2)
        trailer = image.read(512)
        data_at = struct.unpack_from('>Q', trailer, 24)[0]
        xml_at, xml_size = struct.unpack_from('>QQ', trailer, 216)
        sectors = struct.unpack_from('>Q', trailer, 492)[0]
        image.seek(xml_at)
        metadata = plistlib.loads(image.read(xml_size))
        disk.truncate(sectors * 512)
        for partition in metadata['resource-fork']['blkx']:
            table = partition['Data']
            first_sector, _, partition_data = struct.unpack_from('>QQQ', table, 8)
            count = struct.unpack_from('>I', table, 200)[0]
            for index in range(count):
                kind, _, sector, _, offset, size = struct.unpack_from('>IIQQQQ', table, 204 + 40 * index)
                if kind in (0, 2, 0x7ffffffe, 0xffffffff):
                    continue
                image.seek(data_at + partition_data + offset)
                data = image.read(size)
                if kind == 0x80000007:
                    import lzfse
                    data = lzfse.decompress(data)
                elif kind != 1:
                    raise ValueError(f'Unsupported UDIF chunk type {kind:#x}')
                disk.seek((first_sector + sector) * 512)
                disk.write(data)
            print(f"Expanded {partition['Name']}", flush=True)
    print(f'Raw disk: {output} ({sectors * 512} bytes)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    convert(args.source, args.output)


if __name__ == '__main__':
    main()
