#!/usr/bin/env python3
"""Copy the pinned NativeUfs source into a new directory and apply the nabu board patch.

The fixed upstream checkout is never modified: the patch is applied to a fresh copy.
Only the source tree and the small patch file are read, and only the patch file is
hashed. Nothing here compiles, links or runs the driver.

What the result is NOT: the current native base has no ordinary IOBlockStorageDevice
export, so the patched source cannot be linked into it yet. IOStorageFamily bindings
(upstream scripts/prepare-storage-headers.py and build-native-virtio-bindings.py) are
the next step; this script records compiled=false, linked=false, booted=false.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINNED_COMMIT = "af785c1777161a62931425c2faaa536ce0bebd5b"
DEFAULT_PATCH = ROOT / "mac_build/mac-batch-20261022/patches/nabu-nativeufs-board.patch"
REQUIRED = ("NativeUfs.cpp", "RootCommands.h", "SmmuTakeover.h", "GccUfs.h")
TOUCHED = ("NabuBoard.h", "NativeUfs.cpp", "RootCommands.h", "SmmuTakeover.h", "GccUfs.h")


class PrepareError(RuntimeError):
    """The input is not the pinned source, or the patch does not apply."""


def run(args, cwd=None, env=None):
    proc = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise PrepareError("%s failed (%d): %s" % (" ".join(args), proc.returncode,
                                                   (proc.stderr or proc.stdout).strip()))
    return proc.stdout.strip()


def check_source(source: Path, expected: str) -> dict:
    if not source.is_dir():
        raise PrepareError("source is not a directory: %s" % source)
    missing = [name for name in REQUIRED if not (source / name).is_file()]
    if missing:
        raise PrepareError("source is not a NativeUfs tree; missing %s" % ", ".join(missing))
    if not (source / ".git").exists():
        raise PrepareError("source is not a git checkout, so the pinned commit cannot be "
                           "verified; clone %s at %s" % ("https://github.com/UniXNU/NativeUfs.git", expected))
    head = run(["git", "rev-parse", "HEAD"], cwd=source)
    if head != expected:
        raise PrepareError("source HEAD is %s, expected the pinned %s" % (head, expected))
    dirty = run(["git", "status", "--porcelain"], cwd=source)
    if dirty:
        raise PrepareError("source checkout is not clean; refusing to patch an edited tree")
    return {"head": head, "clean": True}


def patch_targets(patch: Path) -> list[str]:
    text = patch.read_text(encoding="utf-8")
    targets = re.findall(r"^diff --git a/(\S+) b/(\S+)$", text, re.M)
    if not targets:
        raise PrepareError("patch has no git diff headers")
    names = [dst for _, dst in targets]
    if sorted(names) != sorted(TOUCHED):
        raise PrepareError("patch touches %s, expected %s" % (sorted(names), sorted(TOUCHED)))
    return names


def apply_patch(output: Path, patch: Path, names: list[str]) -> None:
    for name in names:
        if not (output / name).is_file() and "new file mode" not in patch.read_text(encoding="utf-8"):
            raise PrepareError("patch target %s is absent from the copy" % name)
    # A copy inside another checkout must not inherit its repository prefix:
    # git apply otherwise skips every top-level driver path and returns zero.
    env = os.environ.copy()
    env["GIT_CEILING_DIRECTORIES"] = str(output.parent.resolve())
    run(["git", "apply", "--check", str(patch)], cwd=output, env=env)
    run(["git", "apply", str(patch)], cwd=output, env=env)


def verify_applied(output: Path) -> None:
    board = output / "NabuBoard.h"
    if not board.is_file():
        raise PrepareError("NabuBoard.h was not created")
    facts = board.read_text(encoding="utf-8")
    for needle in ('"qcom,sm8150-ufshc"', "0x0300", "0x00002500ULL", "0x00003000ULL",
                   "logicalBlockBytes", "4096,", "false,"):
        if needle not in facts:
            raise PrepareError("NabuBoard.h lacks %s" % needle)
    source = (output / "NativeUfs.cpp").read_text(encoding="utf-8")
    for needle in ("sm8550-ufshc", "0x15000000ULL", "smmuBypassStream (0x60"):
        if needle in source:
            raise PrepareError("NativeUfs.cpp still carries the sheng value %r" % needle)
    for needle in ("kBoard.streamId", "kBoard.smmuBase", "kBoard.hcMapBytes"):
        if needle not in source:
            raise PrepareError("NativeUfs.cpp does not use %s" % needle)
    bringup = source.split("static bool hostBringUp", 1)[1].split("\n}", 1)[0]
    capacity_check = 'gRootDiagnostic.stage = "LUN block size";'
    if ("READ CAPACITY(10)" not in bringup or
            "blockBytes != nabu_ufs::kBoard.logicalBlockBytes" not in bringup or
            capacity_check not in bringup or
            bringup.index(capacity_check) > bringup.index("gHost.ready = true;")):
        raise PrepareError("hostBringUp must verify the LUN logical block size before enabling reads")
    commands = (output / "RootCommands.h").read_text(encoding="utf-8")
    if "kIOReturnNotPermitted" not in commands or "0x2a" in commands:
        raise PrepareError("RootCommands.h still builds a WRITE(10)")
    for name in ('PE_parse_boot_argn ("sheng-data-persist"', 'PE_parse_boot_argn ("sheng-log"'):
        if name in source:
            raise PrepareError("NativeUfs.cpp still enables the sheng write boot argument %r" % name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, required=True, help="pinned NativeUfs git checkout")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for the patched copy")
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--source-commit", default=PINNED_COMMIT)
    args = parser.parse_args(argv)

    patch = args.patch.resolve()
    if not patch.is_file():
        raise PrepareError("patch is missing: %s" % patch)
    source = args.source.resolve()
    output = args.output_dir.resolve()
    if output.exists():
        raise PrepareError("output directory must not exist: %s" % output)
    if output.is_relative_to(source):
        raise PrepareError("output directory must be outside the source tree: %s" % output)
    identity = check_source(source, args.source_commit)
    names = patch_targets(patch)
    output.mkdir(parents=True)
    shutil.copytree(source, output, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
    apply_patch(output, patch, names)
    verify_applied(output)
    console_patch = patch.with_name('nabu-ufs-inspect-console.patch')
    apply_patch(output, console_patch, ['NativeUfs.cpp'])
    report = {
        "purpose": "nabu SM8150 read-only UFS board port, applied to a copy of the pinned source",
        "source": str(source),
        "source_commit": identity["head"],
        "source_clean": identity["clean"],
        "source_tree_modified": False,
        "patch": str(patch),
        "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
        "inspect_console_patch_sha256": hashlib.sha256(console_patch.read_bytes()).hexdigest(),
        "applied_files": names,
        "output": str(output),
        "compiled": False,
        "linked": False,
        "booted": False,
        "hardware_tested": False,
        "iostorage_bindings_connected": False,
        "note": "The current native base has no ordinary IOBlockStorageDevice export; "
                "IOStorageFamily bindings are the next CI step. Nothing here ran the driver.",
    }
    (output / "nabu-ufs-source.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PrepareError as error:
        print("prepare_nabu_ufs_source: %s" % error, file=sys.stderr)
        raise SystemExit(2)
