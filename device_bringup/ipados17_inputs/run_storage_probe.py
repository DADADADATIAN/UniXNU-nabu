"""Run one bounded QEMU storage experiment and preserve its raw result."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
NEGATIVES = {"no-device", "wrong-capacity", "write-open"}
MD1_DEVICES = {"/dev/md1", "/dev/md1s1"}
PAGE_BYTES = 4096
SHA256 = re.compile(r"[0-9a-f]{64}")


def host_to_linux(path):
    value = str(path.resolve()).replace("\\", "/")
    return "/mnt/" + value[0].lower() + value[2:] if os.name == "nt" else value


def md1_boot_configuration(boot_args):
    """Parse one exact md1 registration, rejecting absent or ambiguous arguments."""
    tokens = boot_args.split() if isinstance(boot_args, str) else []
    enabled = [token for token in tokens if token.startswith("hackios-apfs-md1=")]
    offsets = [token for token in tokens if token.startswith("hackios-apfs-md1-offset=")]
    sizes = [token for token in tokens if token.startswith("hackios-apfs-md1-size=")]
    if (len(enabled) != 1 or enabled[0].split("=", 1)[1] != "1"
            or len(offsets) != 1 or len(sizes) != 1):
        return None
    try:
        offset = int(offsets[0].split("=", 1)[1], 0)
        size = int(sizes[0].split("=", 1)[1], 0)
    except ValueError:
        return None
    if offset < 0 or offset % PAGE_BYTES or size <= 0 or size % PAGE_BYTES:
        return None
    return {"offset": offset, "size": size}


def validate_fixture_case(contract, payload, ramdisk, case):
    """Reject a fixture or embedded image that does not implement the selected case."""
    if not isinstance(contract, dict):
        raise ValueError("fixture contract must be a JSON object")
    if case == "baseline":
        if contract.get("mdev_block_read_probe") or contract.get("apfs_file_read_probe"):
            raise ValueError("baseline requires a fixture without storage probes")
        return
    if not isinstance(payload, dict) or not isinstance(ramdisk, bytes):
        raise ValueError("storage cases require a prepared payload and RAMDisk")
    if contract.get("mdev_block_read_probe") is not True:
        raise ValueError("an own block-read fixture is required")
    if contract.get("mdev_device") not in MD1_DEVICES:
        raise ValueError("block-read fixture must target /dev/md1 or /dev/md1s1")
    if type(contract.get("mdev_read_offset")) is not int or contract["mdev_read_offset"] != 0:
        raise ValueError("md1 fixture must read the block-0 contract")
    write_open = contract.get("mdev_write_open", False)
    if type(write_open) is not bool:
        raise ValueError("mdev_write_open must be an explicit boolean when present")
    if write_open != (case == "write-open"):
        raise ValueError("case and fixture write-open control do not match")
    if case == "apfs-file":
        if contract.get("apfs_file_read_probe") is not True:
            raise ValueError("APFS file experiment requires its matching signed fixture")
    elif contract.get("apfs_file_read_probe") not in (None, False):
        raise ValueError("APFS fixture cannot be used for a non-APFS case")

    offset = payload.get("image_offset")
    image_bytes = payload.get("image_bytes")
    image_sha256 = payload.get("image_sha256")
    if (type(offset) is not int or type(image_bytes) is not int
            or offset <= 0 or offset % PAGE_BYTES or image_bytes <= 0
            or image_bytes % PAGE_BYTES or not isinstance(image_sha256, str)
            or not SHA256.fullmatch(image_sha256)):
        raise ValueError("payload image metadata is invalid")
    if (contract.get("mdev_image_offset") != offset
            or contract.get("mdev_image_bytes") != image_bytes
            or contract.get("mdev_image_sha256") != image_sha256):
        raise ValueError("fixture contract and payload image metadata differ")
    if len(ramdisk) != offset + image_bytes:
        raise ValueError("prepared RAMDisk length does not match its image trailer")
    image = ramdisk[offset:offset + image_bytes]
    if hashlib.sha256(image).hexdigest() != image_sha256:
        raise ValueError("embedded APFS image differs from the payload receipt")
    first = contract.get("buffers", {}).get("_md1_buffer")
    if (not isinstance(first, dict) or first.get("size") != PAGE_BYTES
            or first.get("sha256") != hashlib.sha256(image[:PAGE_BYTES]).hexdigest()):
        raise ValueError("fixture first-block expectation differs from the embedded image")


def expected_refusal(report, case):
    g = report.get("gdb_globals", {})
    contract = report.get("el0_contract", {})
    image_bytes = contract.get("mdev_image_bytes")
    image_offset = contract.get("mdev_image_offset")
    if type(image_bytes) is not int or image_bytes <= 0 or type(image_offset) is not int:
        return False
    configuration = md1_boot_configuration(report.get("boot_args"))
    if report.get("passed") is not False or g.get("_panicstr") != 0:
        return False
    if not (g.get("_md1_open_flags", 0) & 0x20000000):
        return False
    if g.get("_mdev_apfs_md1_reads") != 0:
        return False
    if case == "write-open":
        return (configuration == {"offset": image_offset, "size": image_bytes}
                and g.get("_mdev_apfs_md1_ready") == 1
                and g.get("_mdev_apfs_md1_status") == 0
                and g.get("_mdev_apfs_md1_capacity_bytes") == image_bytes
                and g.get("_md1_open_result") == 30
                and g.get("_mdev_apfs_md1_writes") == 1
                and g.get("_mdev_apfs_md1_write_failures") == 1)
    if case == "wrong-capacity":
        return (configuration == {"offset": image_offset, "size": image_bytes + PAGE_BYTES}
                and g.get("_mdev_apfs_md1_ready") == 0
                and g.get("_mdev_apfs_md1_capacity_bytes") == 0
                and g.get("_md1_open_result") == 2
                and g.get("_mdev_apfs_md1_status") == 22)
    if case == "no-device":
        if any(token.startswith("hackios-apfs-md1")
               for token in report.get("boot_args", "").split()):
            return False
        return (g.get("_mdev_apfs_md1_ready") == 0
                and g.get("_mdev_apfs_md1_capacity_bytes") == 0
                and g.get("_md1_open_result") == 2
                and g.get("_mdev_apfs_md1_status") == -1)
    return False


def expected_success(report, case):
    """Only an APFS-file run that explicitly passed mount and file reads is a success."""
    if report.get("passed") is not True:
        return False
    if case != "apfs-file":
        return True
    return (report.get("apfs_mount_tested") is True
            and report.get("apfs_readonly_file_test_passed") is True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--case", choices=("baseline", "block-read", "apfs-file", *sorted(NEGATIVES)), required=True)
    for name in ("kernel", "prelink-report", "fixture-dir", "adt", "unixnu", "darwinboot", "output-dir"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--wsl-distro", default="kali-linux")
    p.add_argument("--mdev-iomedia", action="store_true", help="publish genuine IOMedia identities for the APFS file case")
    args = p.parse_args()
    if args.mdev_iomedia and args.case != "apfs-file":
        p.error("--mdev-iomedia requires --case apfs-file")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", args.label):
        p.error("label must be a unique filename-safe name")
    raw_path = ROOT / "device_bringup/out" / ("qemu-nabu-" + args.label + "-result.json")
    if raw_path.exists() or args.output_dir.exists():
        p.error("run label/output already used; preserve the old observation")
    fixture = args.fixture_dir.resolve()
    contract_path = fixture / "el0-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    boot = "-v serial=3 debug=0x14e kt_fixed_zones=120 cpus=1 rd=md0"
    if args.case != "baseline":
        payload = json.loads((fixture / "payload.json").read_text(encoding="utf-8"))
        data = (fixture / "launchd.macho").read_bytes()
        if hashlib.sha256(data).hexdigest() != payload["ramdisk_sha256"]:
            p.error("RAMDisk differs from the prepared payload")
        try:
            validate_fixture_case(contract, payload, data, args.case)
        except (KeyError, TypeError, ValueError) as exc:
            p.error(str(exc))
        if args.case != "no-device":
            size = payload["image_bytes"] + (PAGE_BYTES if args.case == "wrong-capacity" else 0)
            boot += (f" hackios-apfs-md1=1 hackios-apfs-md1-offset={payload['image_offset']:#x}"
                     f" hackios-apfs-md1-size={size:#x}")
    else:
        try:
            validate_fixture_case(contract, None, None, args.case)
        except (KeyError, TypeError, ValueError) as exc:
            p.error(str(exc))
    if args.mdev_iomedia:
        boot += " hackios-apfs-iomedia=1"
    command = [
        "python3" if os.name == "nt" else sys.executable,
        host_to_linux(ROOT / "device_bringup/test_nabu_qemu.py"),
        "--kernel", host_to_linux(args.kernel),
        "--prelink-report", host_to_linux(args.prelink_report),
        "--crypto-provider", "original-prelinked-native", "--require-apfs-registration",
        "--initrd", host_to_linux(fixture / "launchd.macho"),
        "--el0-contract", host_to_linux(contract_path),
        "--adt", host_to_linux(args.adt), "--unixnu", host_to_linux(args.unixnu),
        "--darwinboot", host_to_linux(args.darwinboot),
        "--qemu-virt-gic", "--post-handoff-seconds", "8", "--boot-args", boot,
        "--label", args.label,
    ]
    if os.name == "nt":
        command = ["wsl", "-d", args.wsl_distro, "--", *command]
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
    with (args.output_dir / "harness.log").open("xb") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    if not raw_path.is_file():
        raise SystemExit("harness produced no raw report; inspect " + str(args.output_dir / "harness.log"))
    report = json.loads(raw_path.read_text(encoding="utf-8"))
    accepted = (result.returncode != 0 and expected_refusal(report, args.case)
                if args.case in NEGATIVES else result.returncode == 0 and expected_success(report, args.case))
    summary = {
        "case": args.case, "raw_report": str(raw_path), "raw_harness_passed": report["passed"],
        "harness_exit_code": result.returncode, "expected_outcome_observed": accepted,
        "apfs_mount_tested": report.get("apfs_mount_tested", False),
        "apfs_readonly_file_test_passed": report.get("apfs_readonly_file_test_passed", False),
        "apple_launchd_tested": False, "device_accessed": False,
    }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
