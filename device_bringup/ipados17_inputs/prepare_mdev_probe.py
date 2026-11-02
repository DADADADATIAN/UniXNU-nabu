"""Append the verified APFS fixture to an own Mach-O RAMDisk, for md1 tests."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct

from apfs_fixture import load_report


def prepare(fixture_dir, image, image_report, output):
    report = load_report(image_report, image)
    if report.get("creation_passed") is not True:
        raise ValueError("image report does not prove successful fixture creation")
    image_data = image.read_bytes()
    if (len(image_data) != report["image_bytes"]
            or hashlib.sha256(image_data).hexdigest() != report["image_sha256"]):
        raise ValueError("image changed after metadata validation")
    own = (fixture_dir / "launchd.macho").read_bytes()
    if len(own) < 32 or struct.unpack_from("<I", own)[0] != 0xfeedfacf:
        raise ValueError("own instrument is not a Mach-O")
    contract = json.loads((fixture_dir / "el0-contract.json").read_text(encoding="utf-8"))
    if contract.get("mdev_block_read_probe") is not True:
        raise ValueError("fixture was not built for actual md1 reads")
    offset = (len(own) + 4095) & ~4095
    if contract.get("mdev_device") == "/dev/md0":
        slot = contract["mdev_read_offset"]
        if offset > slot:
            raise ValueError("own Mach-O overlaps the fixed md0 probe offset")
        offset = slot
    payload = own + bytes(offset - len(own)) + image_data
    if len(payload) >= 64 * 1024 * 1024:
        raise ValueError("combined RAMDisk exceeds the experimental 64-MiB budget")
    contract.setdefault("buffers", {}).update({
        "_md1_buffer": {"size": 4096, "sha256": hashlib.sha256(payload[offset:offset + 4096]).hexdigest()}
    })
    contract["mdev_image_offset"] = offset
    contract["mdev_image_bytes"] = report["image_bytes"]
    contract["mdev_image_sha256"] = report["image_sha256"]
    output.mkdir(parents=True, exist_ok=False)
    (output / "launchd.macho").write_bytes(payload)
    shutil.copyfile(fixture_dir / "addresses.json", output / "addresses.json")
    (output / "el0-contract.json").write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    receipt = {
        "format": "own Mach-O with an APFS payload trailer inside the loader RAMDisk",
        "own_macho_bytes": len(own), "own_macho_sha256": hashlib.sha256(own).hexdigest(),
        "ramdisk_bytes": len(payload), "ramdisk_sha256": hashlib.sha256(payload).hexdigest(),
        "image_offset": offset, "image_bytes": report["image_bytes"],
        "image_sha256": report["image_sha256"], "expected_first_block_sha256": contract["buffers"]["_md1_buffer"]["sha256"],
        "runtime_tested": False, "apfs_mount_tested": False, "apple_launchd_tested": False,
    }
    (output / "payload.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--image-report", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.fixture_dir, args.image, args.image_report, args.output_dir), indent=2))


if __name__ == "__main__":
    main()
