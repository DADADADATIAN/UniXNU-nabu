#!/usr/bin/env python3
"""Create and verify a small, single-volume, unencrypted APFS fixture.

The APFS image itself is produced only on macOS.  This module also provides
the portable checks used before a fixture is allowed into the QEMU harness:
the host-side layout is validated, but no guest observation is implied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from typing import Any


PROBE_CONTENT = b"HACKIOS_APFS_PROBE_V1\n"
PROBE_SHA256 = hashlib.sha256(PROBE_CONTENT).hexdigest()
MAX_IMAGE_BYTES = 64 * 1024 * 1024
PAGE_BYTES = 4096
MIN_IMAGE_BYTES = 32 * 1024 * 1024


class FixtureError(RuntimeError):
    """The fixture or its metadata violates the offline storage contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_host_metadata(metadata: dict[str, Any], image: Path) -> None:
    """Validate the host-side facts before a run can use the fixture."""
    if metadata.get("format") != "raw":
        raise FixtureError("fixture must be a raw image")
    if metadata.get("encrypted") is not False:
        raise FixtureError("fixture must be explicitly unencrypted")
    if metadata.get("single_volume") is not True:
        raise FixtureError("fixture must contain exactly one APFS volume")
    if metadata.get("probe_path") != "/probe.bin":
        raise FixtureError("fixture probe path must be /probe.bin")
    if metadata.get("probe_sha256") != PROBE_SHA256:
        raise FixtureError("fixture probe hash is not the fixed probe")
    if metadata.get("probe_size") != len(PROBE_CONTENT):
        raise FixtureError("fixture probe size does not match the fixed probe")
    if not image.is_file():
        raise FixtureError("fixture image is missing")
    size = image.stat().st_size
    if size != metadata.get("image_bytes"):
        raise FixtureError("fixture metadata size does not match the image")
    if size <= 0 or size >= MAX_IMAGE_BYTES:
        raise FixtureError("fixture exceeds the 64 MiB contract")
    if size % PAGE_BYTES:
        raise FixtureError("fixture is not a whole number of 4 KiB pages")
    if sha256_file(image) != metadata.get("image_sha256"):
        raise FixtureError("fixture image hash does not match metadata")
    with image.open("rb") as stream:
        stream.seek(32)
        header = stream.read(16)
    if len(header) != 16 or header[:4] != b"NXSB":
        raise FixtureError("fixture has no APFS container superblock magic at offset 32")
    block_size, block_count = struct.unpack_from("<IQ", header, 4)
    if block_size != PAGE_BYTES or block_count * block_size != size:
        raise FixtureError("fixture container geometry does not match its raw image")


def build_fixture(output_dir: Path, *, size_mib: int = 32) -> dict[str, Any]:
    """Use the same generator exported to Actions; never maintain two formatters."""
    if sys.platform != "darwin":
        raise FixtureError("APFS fixture creation requires macOS hdiutil/diskutil")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FixtureError("output directory must be absent or empty")
    generator = Path(__file__).resolve().parents[2] / "mac_build/mac-batch-20261022/make_apfs_fixture.py"
    subprocess.run([sys.executable, str(generator), "--output-dir", str(output_dir),
                    "--size-mib", str(size_mib)], check=True)
    return load_report(output_dir / "apfs-probe.json", output_dir / "apfs-probe.raw")


def load_report(report_path: Path, image: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate_host_metadata(report, image)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--size-mib", type=int, default=32)
    args = parser.parse_args(argv)
    report = build_fixture(args.output_dir, size_mib=args.size_mib)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
