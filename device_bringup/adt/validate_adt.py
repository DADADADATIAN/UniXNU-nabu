#!/usr/bin/env python3
"""validate_adt.py - Independent host-side validator for nabu Apple ADT.

Strictly validates Apple Device Tree (ADT) binaries against XNU kernel,
ArmDTPlatform, ArmCpu, and DarwinBoot hardware and ABI requirements.
Pure standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ADTParseError(Exception):
    """Raised when the ADT binary violates the Apple ADT wire format."""
    pass


class ADTNode:
    """Represents a node in an Apple Device Tree."""

    def __init__(self, name: str):
        self.name: str = name
        self.properties: Dict[str, bytes] = {}
        self.children: List[ADTNode] = []

    def add_property(self, key: str, value: bytes) -> None:
        if key in self.properties:
            raise ADTParseError(f"Duplicate property '{key}' in node '{self.name}'")
        self.properties[key] = value

    def add_child(self, child: ADTNode) -> None:
        self.children.append(child)

    def find_node(self, path: str) -> Optional[ADTNode]:
        """Find a node by path (e.g. '/chosen/memory-map' or 'cpus/cpu@0')."""
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return self

        current = self
        for part in parts:
            found = None
            for child in current.children:
                if child.name == part:
                    found = child
                    break
            if not found:
                return None
            current = found
        return current

    def get_property(self, key: str) -> Optional[bytes]:
        return self.properties.get(key)

    def get_u32(self, key: str) -> Optional[int]:
        val = self.properties.get(key)
        if val is not None and len(val) >= 4:
            return struct.unpack("<I", val[:4])[0]
        return None

    def get_u64(self, key: str) -> Optional[int]:
        val = self.properties.get(key)
        if val is not None and len(val) >= 8:
            return struct.unpack("<Q", val[:8])[0]
        return None

    def get_str(self, key: str) -> Optional[str]:
        val = self.properties.get(key)
        if val is not None and val.endswith(b"\0"):
            try:
                return val[:-1].decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize node and its subtree to a JSON-serializable dictionary."""
        props_dict = {}
        for k, v in self.properties.items():
            if v.endswith(b"\0") and all(32 <= b < 127 or b in (9, 10, 13) for b in v[:-1]):
                try:
                    props_dict[k] = {"type": "string", "value": v[:-1].decode("utf-8")}
                    continue
                except UnicodeDecodeError:
                    pass
            if len(v) == 4:
                u32 = struct.unpack("<I", v)[0]
                props_dict[k] = {"type": "u32", "value": f"0x{u32:x} ({u32})"}
            elif len(v) == 8:
                u64 = struct.unpack("<Q", v)[0]
                props_dict[k] = {"type": "u64", "value": f"0x{u64:x} ({u64})"}
            elif len(v) <= 16:
                props_dict[k] = {"type": "hex", "value": v.hex(" ")}
            else:
                props_dict[k] = {"type": "bytes", "length": len(v), "preview": v[:16].hex(" ") + "..."}

        return {
            "name": self.name,
            "properties": props_dict,
            "children": [c.to_dict() for c in self.children]
        }

    def dump(self, indent: int = 0) -> str:
        """Produce a formatted human-readable tree dump."""
        prefix = "  " * indent
        lines = [f"{prefix}{self.name} {{"]
        for k, v in self.properties.items():
            if k == "name":
                continue
            # Format representation
            if v.endswith(b"\0") and all(32 <= b < 127 or b in (9, 10, 13) for b in v[:-1]):
                try:
                    repr_val = f'"{v[:-1].decode("utf-8")}"'
                except UnicodeDecodeError:
                    repr_val = f"<{len(v)} bytes hex: {v.hex(' ')}>"
            elif len(v) == 4:
                u32 = struct.unpack("<I", v)[0]
                repr_val = f"<0x{u32:08x}>"
            elif len(v) == 8:
                u64 = struct.unpack("<Q", v)[0]
                repr_val = f"<0x{u64:016x}>"
            elif len(v) == 24 and k == "ranges":
                u = struct.unpack("<3Q", v)
                repr_val = f"<0x{u[0]:x} 0x{u[1]:x} 0x{u[2]:x}>"
            elif len(v) == 32 and k == "reg":
                u = struct.unpack("<4Q", v)
                repr_val = f"<0x{u[0]:x} 0x{u[1]:x} 0x{u[2]:x} 0x{u[3]:x}>"
            elif len(v) <= 16:
                repr_val = f"[{v.hex(' ')}]"
            else:
                repr_val = f"[{len(v)} bytes: {v[:16].hex(' ')} ...]"
            lines.append(f"{prefix}  {k} = {repr_val};")

        for child in self.children:
            lines.append(child.dump(indent + 1))
        lines.append(f"{prefix}}};")
        return "\n".join(lines)


def parse_adt(data: bytes) -> ADTNode:
    """Strictly parse raw Apple ADT binary.

    Enforces wire format rules derived from DarwinBoot AdtNode() and XNU:
    - Node: LE u32 nproperties, LE u32 nchildren
    - Property: 32-byte key (must contain NUL terminator), LE u32 length (no flag bits),
      data bytes padded to 4-byte alignment
    - Bounds checking (DarwinBoot: properties <= rem/36, children <= rem/8, depth <= 64)
    - Rejects truncation, trailing bytes, duplicate keys, missing node names.
    """
    total_len = len(data)
    if total_len < 8:
        raise ADTParseError(f"ADT data too short ({total_len} bytes, minimum header is 8 bytes)")

    def _parse_node(offset: int, depth: int) -> Tuple[ADTNode, int]:
        if depth > 64:
            raise ADTParseError(f"ADT exceeds maximum depth 64 at offset {offset}")
        if total_len - offset < 8:
            raise ADTParseError(f"Truncated node header at offset {offset}")

        nprops, nchildren = struct.unpack_from("<II", data, offset)
        offset += 8

        # DarwinBoot.c:207,257 bounds validation against malicious counts
        remaining = total_len - offset
        if nprops > remaining // 36:
            raise ADTParseError(f"Oversize property count {nprops} exceeds remaining space {remaining} at offset {offset}")

        node_props: Dict[str, bytes] = {}
        node_name: Optional[str] = None

        for _ in range(nprops):
            if total_len - offset < 36:
                raise ADTParseError(f"Truncated property header at offset {offset}")

            raw_key = data[offset:offset + 32]
            if b"\0" not in raw_key:
                raise ADTParseError(f"Property name not NUL-terminated within 32 bytes at offset {offset}")

            nul_pos = raw_key.index(b"\0")
            try:
                key = raw_key[:nul_pos].decode("ascii")
            except UnicodeDecodeError:
                raise ADTParseError(f"Property name contains invalid non-ASCII characters at offset {offset}")

            if not key:
                raise ADTParseError(f"Property name is empty at offset {offset}")

            if not all(32 <= ord(c) < 127 for c in key):
                raise ADTParseError(f"Property name '{key}' contains garbled non-printable characters at offset {offset}")

            val_len = struct.unpack_from("<I", data, offset + 32)[0]
            offset += 36

            # DarwinBoot doesn't mask flags; bit 31 set would cause length > remaining
            if val_len & 0x80000000:
                raise ADTParseError(f"Property '{key}' has high flag bits set in length (0x{val_len:08x}) at offset {offset}")

            if val_len > total_len - offset:
                raise ADTParseError(f"Property '{key}' length {val_len} exceeds file bounds at offset {offset}")

            val = data[offset:offset + val_len]
            offset += val_len

            # 4-byte alignment padding
            pad = (-val_len) % 4
            if offset + pad > total_len:
                raise ADTParseError(f"Truncated alignment padding for property '{key}' at offset {offset}")
            offset += pad

            if key in node_props:
                raise ADTParseError(f"Duplicate property key '{key}' at offset {offset}")
            node_props[key] = val

            if key == "name":
                if not val.endswith(b"\0"):
                    raise ADTParseError(f"Node 'name' property not NUL-terminated at offset {offset}")
                try:
                    node_name = val[:-1].decode("ascii")
                except UnicodeDecodeError:
                    raise ADTParseError(f"Node 'name' property is not ASCII at offset {offset}")
                if not node_name or not all(32 <= ord(c) < 127 for c in node_name):
                    raise ADTParseError(f"Node 'name' property is empty or garbled at offset {offset}")

        if node_name is None:
            raise ADTParseError(f"Missing required 'name' property for node at offset {offset}")

        node = ADTNode(node_name)
        for k, v in node_props.items():
            node.add_property(k, v)

        remaining = total_len - offset
        if nchildren > remaining // 8:
            raise ADTParseError(f"Oversize child count {nchildren} exceeds remaining space {remaining} at offset {offset}")

        for _ in range(nchildren):
            child_node, offset = _parse_node(offset, depth + 1)
            node.add_child(child_node)

        return node, offset

    root, final_offset = _parse_node(0, 0)
    if final_offset < total_len:
        trailing = total_len - final_offset
        raise ADTParseError(f"ADT contains {trailing} trailing unparsed byte(s) after root node")

    return root


@dataclass
class CheckResult:
    check_id: str
    name: str
    status: str  # "PASS", "FAIL", "WARN"
    detail: str
    source_ref: str


def check_parse_strict(data: bytes) -> Tuple[Optional[ADTNode], CheckResult]:
    source_ref = "DarwinBoot/source/DarwinBootPkg/Driver/DarwinBoot.c:183-262"
    try:
        root = parse_adt(data)
        # Count total nodes and properties
        def _count(node: ADTNode) -> Tuple[int, int]:
            n = 1
            p = len(node.properties)
            for c in node.children:
                cn, cp = _count(c)
                n += cn
                p += cp
            return n, p

        total_nodes, total_props = _count(root)
        return root, CheckResult(
            check_id="parse_strict",
            name="Strict ADT Binary Parsing",
            status="PASS",
            detail=f"Parsed {total_nodes} nodes and {total_props} properties; no truncation or trailing bytes",
            source_ref=source_ref
        )
    except ADTParseError as e:
        return None, CheckResult(
            check_id="parse_strict",
            name="Strict ADT Binary Parsing",
            status="FAIL",
            detail=f"ADT parse error: {e}",
            source_ref=source_ref
        )
    except Exception as e:
        return None, CheckResult(
            check_id="parse_strict",
            name="Strict ADT Binary Parsing",
            status="FAIL",
            detail=f"Unexpected error during ADT parse: {e}",
            source_ref=source_ref
        )


def check_root_name(root: ADTNode) -> CheckResult:
    source_ref = "ArmDTPlatform/source/Info.plist:14; ArmDTPlatform.cpp:5"
    if root.name == "device-tree":
        return CheckResult("root_name", "Root Node Name", "PASS", "Root name is 'device-tree'", source_ref)
    return CheckResult("root_name", "Root Node Name", "FAIL", f"Root node name is '{root.name}', expected 'device-tree'", source_ref)


def check_required_nodes(root: ADTNode) -> CheckResult:
    source_ref = "ArmDTPlatform/source/ArmDTPlatform.cpp:61,125-138"
    required = ["cpus", "arm-io", "defaults", "options", "chosen"]
    missing = [req for req in required if root.find_node(req) is None]
    if not missing:
        return CheckResult("required_nodes", "Required Top-Level Nodes", "PASS", f"All required nodes present: {', '.join(required)}", source_ref)
    return CheckResult("required_nodes", "Required Top-Level Nodes", "FAIL", f"Missing required top-level node(s): {', '.join(missing)}", source_ref)


def check_nvram_proxy_props(root: ADTNode) -> CheckResult:
    source_ref = "ArmDTPlatform/source/ArmDTPlatform.cpp:65-68"
    chosen = root.find_node("chosen")
    if not chosen:
        return CheckResult("nvram_proxy_props", "NVRAM Proxy Properties", "FAIL", "Missing /chosen node", source_ref)

    bank_size_bytes = chosen.get_property("nvram-bank-size")
    proxy_data_bytes = chosen.get_property("nvram-proxy-data")

    if bank_size_bytes is None:
        return CheckResult("nvram_proxy_props", "NVRAM Proxy Properties", "FAIL", "Missing /chosen/nvram-bank-size", source_ref)
    if len(bank_size_bytes) != 4:
        return CheckResult("nvram_proxy_props", "NVRAM Proxy Properties", "FAIL", f"/chosen/nvram-bank-size length is {len(bank_size_bytes)} bytes, expected 4", source_ref)

    if proxy_data_bytes is None:
        return CheckResult("nvram_proxy_props", "NVRAM Proxy Properties", "FAIL", "Missing /chosen/nvram-proxy-data", source_ref)
    if len(proxy_data_bytes) == 0:
        return CheckResult("nvram_proxy_props", "NVRAM Proxy Properties", "FAIL", "/chosen/nvram-proxy-data is empty (length 0)", source_ref)

    bank_size = struct.unpack("<I", bank_size_bytes)[0]
    return CheckResult("nvram_proxy_props", "NVRAM Proxy Properties", "PASS", f"nvram-bank-size={bank_size} (4 bytes), nvram-proxy-data non-empty ({len(proxy_data_bytes)} bytes)", source_ref)


def check_chrp_nvram_image(root: ADTNode) -> CheckResult:
    source_ref = "scratch/iokit/Kernel/IONVRAMCHRPHandler.cpp:190-207,428-433; scripts/qemu-entry/make-dt.py:26-46"
    chosen = root.find_node("chosen")
    if not chosen:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", "Missing /chosen node", source_ref)

    bank_size_bytes = chosen.get_property("nvram-bank-size")
    bank_count_bytes = chosen.get_property("nvram-bank-count")
    cur_bank_bytes = chosen.get_property("nvram-current-bank")
    proxy_data = chosen.get_property("nvram-proxy-data")

    if not bank_size_bytes or len(bank_size_bytes) != 4:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", "Invalid or missing nvram-bank-size", source_ref)
    bank_size = struct.unpack("<I", bank_size_bytes)[0]
    if bank_size != 8192:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"nvram-bank-size is {bank_size}, expected 8192 (8 KiB)", source_ref)

    if not bank_count_bytes or len(bank_count_bytes) != 4:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", "Missing or invalid nvram-bank-count (must be 4 bytes)", source_ref)
    bank_count = struct.unpack("<I", bank_count_bytes)[0]
    if bank_count != 1:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"nvram-bank-count is {bank_count}, expected 1", source_ref)

    if not cur_bank_bytes or len(cur_bank_bytes) != 4:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", "Missing or invalid nvram-current-bank (must be 4 bytes)", source_ref)
    cur_bank = struct.unpack("<I", cur_bank_bytes)[0]
    if cur_bank != 0:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"nvram-current-bank is {cur_bank}, expected 0", source_ref)

    if not proxy_data or len(proxy_data) != 8192:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"nvram-proxy-data size is {len(proxy_data) if proxy_data else 0}, expected 8192", source_ref)

    # Validate CHRP headers: nvram at 0, common at 32, free at 2096
    def _verify_header(offset: int, expected_name: bytes, expected_len_bytes: int) -> Optional[str]:
        if offset + 16 > len(proxy_data):
            return f"Header at {offset} out of bounds"
        hdr = proxy_data[offset:offset + 16]
        sig, cksum, len_blocks, name = struct.unpack("<BBH12s", hdr)
        if sig != 0x70:
            return f"Header at {offset} signature 0x{sig:02x} != 0x70"
        if len_blocks != expected_len_bytes // 16:
            return f"Header at {offset} block count {len_blocks} != {expected_len_bytes // 16}"
        clean_name = name.split(b"\0")[0]
        if clean_name != expected_name:
            return f"Header at {offset} name '{clean_name.decode(errors='replace')}' != '{expected_name.decode()}'"
        # Checksum calculation: sum of all bytes with cksum byte set to 0, folded to <= 255
        test_hdr = bytearray(hdr)
        test_hdr[1] = 0
        s = sum(test_hdr)
        while s > 255:
            s = (s & 255) + (s >> 8)
        if (s & 0xff) != cksum:
            return f"Header at {offset} ('{expected_name.decode()}') checksum 0x{cksum:02x} != calculated 0x{s & 0xff:02x}"
        return None

    err = _verify_header(0, b"nvram", 32)
    if err:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"CHRP 'nvram' partition error: {err}", source_ref)

    err = _verify_header(32, b"common", 16 + 2048)
    if err:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"CHRP 'common' partition error: {err}", source_ref)

    free_at = 32 + 16 + 2048  # 2096
    err = _verify_header(free_at, b"free", len(proxy_data) - free_at)
    if err:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"CHRP 'free' partition error: {err}", source_ref)

    # Validate Adler32 checksum at offset 16 of image
    stored_adler = struct.unpack_from("<I", proxy_data, 16)[0]
    calc_adler = zlib.adler32(proxy_data[20:])
    if stored_adler != calc_adler:
        return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "FAIL", f"CHRP Adler32 mismatch: stored 0x{stored_adler:08x} != calculated 0x{calc_adler:08x}", source_ref)

    return CheckResult("chrp_nvram_image", "CHRP NVRAM Structure", "PASS", "8 KiB CHRP image with valid 'nvram', 'common', 'free' headers and Adler-32 checksum", source_ref)


def check_random_seed(root: ADTNode) -> CheckResult:
    source_ref = "scratch/xnu_all/pexpert/gen/pe_gen.c:177-189; docs/porting/device-tree.md:65"
    chosen = root.find_node("chosen")
    if not chosen:
        return CheckResult("random_seed", "Kernel Random Seed", "FAIL", "Missing /chosen node", source_ref)

    seed = chosen.get_property("random-seed")
    if seed is None:
        return CheckResult("random_seed", "Kernel Random Seed", "FAIL", "Missing /chosen/random-seed property", source_ref)
    if len(seed) != 64:
        return CheckResult("random_seed", "Kernel Random Seed", "FAIL", f"/chosen/random-seed length is {len(seed)} bytes, expected exactly 64", source_ref)
    if all(b == 0 for b in seed):
        return CheckResult("random_seed", "Kernel Random Seed", "FAIL", "/chosen/random-seed is all zeros (kernel will panic)", source_ref)

    return CheckResult("random_seed", "Kernel Random Seed", "PASS", "64-byte non-zero random-seed present in /chosen", source_ref)


def check_osenvironment(root: ADTNode) -> CheckResult:
    source_ref = "scratch/xnu_all/bsd/kern/kern_mib.c:709-710; docs/porting/device-tree.md:68"
    chosen = root.find_node("chosen")
    if not chosen:
        return CheckResult("osenvironment", "OS Environment", "FAIL", "Missing /chosen node", source_ref)

    raw_env = chosen.get_property("osenvironment")
    if raw_env is None:
        return CheckResult("osenvironment", "OS Environment", "FAIL", "Missing /chosen/osenvironment property", source_ref)
    if not raw_env.endswith(b"\0"):
        return CheckResult("osenvironment", "OS Environment", "FAIL", "/chosen/osenvironment is not NUL-terminated", source_ref)

    env_str = raw_env[:-1].decode("utf-8", errors="replace")
    valid_envs = {"main", "recoveryos", "ramdisk"}
    if env_str not in valid_envs:
        return CheckResult("osenvironment", "OS Environment", "FAIL", f"/chosen/osenvironment '{env_str}' is not in valid set {valid_envs}", source_ref)

    return CheckResult("osenvironment", "OS Environment", "PASS", f"/chosen/osenvironment is '{env_str}'", source_ref)


def check_dram_contract(root: ADTNode) -> CheckResult:
    source_ref = "dram-contract.md:58-60; scratch/xnu_all/osfmk/arm/arm_init.c:633-639"
    chosen = root.find_node("chosen")
    if not chosen:
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", "Missing /chosen node", source_ref)

    dram_base_bytes = chosen.get_property("dram-base")
    dram_size_bytes = chosen.get_property("dram-size")

    if not dram_base_bytes or len(dram_base_bytes) != 8:
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", f"/chosen/dram-base missing or not 8 bytes (len={len(dram_base_bytes) if dram_base_bytes else 0})", source_ref)
    if not dram_size_bytes or len(dram_size_bytes) != 8:
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", f"/chosen/dram-size missing or not 8 bytes (len={len(dram_size_bytes) if dram_size_bytes else 0})", source_ref)

    dram_base = struct.unpack("<Q", dram_base_bytes)[0]
    dram_size = struct.unpack("<Q", dram_size_bytes)[0]
    dram_end = dram_base + dram_size

    expected_base = 0xc0000000
    expected_size = 0x140000000  # 5 GiB

    if dram_base != expected_base:
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", f"dram-base is 0x{dram_base:x}, expected 0x{expected_base:x}", source_ref)
    if dram_size != expected_size:
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", f"dram-size is 0x{dram_size:x}, expected 0x{expected_size:x} (5 GiB)", source_ref)

    # Check hole overlap: 0xb9900000 to 0xc0000000 (103 MiB gap)
    hole_start = 0xb9900000
    hole_end = 0xc0000000
    if max(dram_base, hole_start) < min(dram_end, hole_end):
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", f"DRAM range [0x{dram_base:x}, 0x{dram_end:x}) overlaps the hardware hole [0x{hole_start:x}, 0x{hole_end:x})", source_ref)

    # Check framebuffer: 0x9c000000, size 0xfa0000 (ends at 0x9cfa0000)
    fb_start = 0x9c000000
    fb_end = fb_start + 0x00fa0000
    if max(dram_base, fb_start) < min(dram_end, fb_end):
        return CheckResult("dram_contract", "Nabu DRAM Contract", "FAIL", f"Framebuffer [0x{fb_start:x}, 0x{fb_end:x}) must be strictly outside DRAM range [0x{dram_base:x}, 0x{dram_end:x})", source_ref)

    return CheckResult("dram_contract", "Nabu DRAM Contract", "PASS", f"dram-base=0x{dram_base:x}, dram-size=0x{dram_size:x} (5 GiB), no hole overlap, framebuffer outside DRAM", source_ref)


def check_darwinboot_memory_size(root: ADTNode) -> CheckResult:
    source_ref = "DarwinBoot/source/DarwinBootPkg/Driver/WindowSize.h:6-8; dram-contract.md:61"
    chosen = root.find_node("chosen")
    if not chosen:
        return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "FAIL", "Missing /chosen node", source_ref)

    raw_mem = chosen.get_property("darwinboot-memory-size")
    if raw_mem is None:
        return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "FAIL", "Missing /chosen/darwinboot-memory-size property", source_ref)
    if len(raw_mem) != 8:
        return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "FAIL", f"/chosen/darwinboot-memory-size length is {len(raw_mem)} bytes, expected 8", source_ref)

    window_size = struct.unpack("<Q", raw_mem)[0]
    min_size = 0x10000000    # 256 MiB
    max_size = 0x200000000   # 8 GiB
    block_align = 0x200000   # 2 MiB

    if window_size < min_size or window_size > max_size:
        return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "FAIL", f"darwinboot-memory-size 0x{window_size:x} ({window_size // 1024 // 1024} MiB) outside valid range 256 MiB - 8 GiB", source_ref)

    if window_size & (block_align - 1) != 0:
        return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "FAIL", f"darwinboot-memory-size 0x{window_size:x} is not 2 MiB aligned", source_ref)

    # Must fit in DRAM
    dram_size_bytes = chosen.get_property("dram-size")
    if dram_size_bytes and len(dram_size_bytes) == 8:
        dram_size = struct.unpack("<Q", dram_size_bytes)[0]
        if window_size > dram_size:
            return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "FAIL", f"darwinboot-memory-size 0x{window_size:x} exceeds DRAM size 0x{dram_size:x}", source_ref)

    return CheckResult("darwinboot_memory_size", "DarwinBoot Memory Window Size", "PASS", f"darwinboot-memory-size=0x{window_size:x} ({window_size // 1024 // 1024} MiB), 2 MiB aligned, within DRAM", source_ref)


def check_cpu_topology(root: ADTNode) -> CheckResult:
    source_ref = "ArmCpu/source/ArmCpu.cpp:175-194; AGENT_HANDOFF.zh-CN.md:408-409"
    cpus = root.find_node("cpus")
    if not cpus:
        return CheckResult("cpu_topology", "CPU Topology", "FAIL", "Missing /cpus node", source_ref)

    # ArmCpu searches children of /cpus with device_type == "cpu"
    cpu_children = [c for c in cpus.children if c.get_property("device_type") == b"cpu\0"]
    if not cpu_children:
        # Check if child is present but with wrong device_type
        if cpus.children:
            dt = cpus.children[0].get_property("device_type")
            return CheckResult("cpu_topology", "CPU Topology", "FAIL", f"CPU node '{cpus.children[0].name}' has device_type={dt!r}, expected b'cpu\\0'", source_ref)
        return CheckResult("cpu_topology", "CPU Topology", "FAIL", "No CPU nodes found under /cpus", source_ref)

    if len(cpu_children) > 1 or len(cpus.children) > 1:
        names = [c.name for c in cpus.children]
        return CheckResult("cpu_topology", "CPU Topology", "FAIL", f"Found secondary CPU node(s): {names}. Controlled pass requires single core (cpu@0/cpu0 only)", source_ref)

    boot_cpu = cpu_children[0]
    reg_bytes = boot_cpu.get_property("reg")
    if not reg_bytes or len(reg_bytes) < 4:
        return CheckResult("cpu_topology", "CPU Topology", "FAIL", f"CPU node '{boot_cpu.name}' missing or truncated 'reg' property", source_ref)

    phys_id = struct.unpack("<I", reg_bytes[:4])[0]
    if phys_id != 0:
        return CheckResult("cpu_topology", "CPU Topology", "FAIL", f"CPU node '{boot_cpu.name}' reg ID is {phys_id}, expected 0", source_ref)

    # Check for sheng-smp anywhere in chosen or defaults
    chosen = root.find_node("chosen")
    if chosen and (chosen.get_property("sheng-smp") is not None):
        return CheckResult("cpu_topology", "CPU Topology", "FAIL", "Forbidden property 'sheng-smp' found in /chosen", source_ref)

    # Check node name ambiguity (cpu@0 vs cpu0)
    status = "PASS"
    detail = f"Single core '{boot_cpu.name}' with device_type='cpu' and reg=0; no secondary CPU nodes or sheng-smp"
    if boot_cpu.name not in ("cpu@0", "cpu0"):
        status = "WARN"
        detail += f" (Note: node name '{boot_cpu.name}' is non-standard; expected 'cpu@0' or 'cpu0')"

    return CheckResult("cpu_topology", "CPU Topology", status, detail, source_ref)


def check_arm_io_ranges(root: ADTNode) -> CheckResult:
    source_ref = "ArmCpu/source/ArmCpu.cpp:205-217; AGENT_HANDOFF.zh-CN.md:414-419"
    arm_io = root.find_node("arm-io")
    if not arm_io:
        return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "FAIL", "Missing /arm-io node", source_ref)

    ac = arm_io.get_u32("#address-cells")
    sc = arm_io.get_u32("#size-cells")
    if ac != 2:
        return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "FAIL", f"/arm-io #address-cells is {ac}, expected 2", source_ref)
    if sc != 2:
        return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "FAIL", f"/arm-io #size-cells is {sc}, expected 2", source_ref)

    ranges = arm_io.get_property("ranges")
    if ranges is None:
        return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "FAIL", "Missing /arm-io/ranges property", source_ref)
    if len(ranges) != 24:
        return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "FAIL", f"/arm-io/ranges length is {len(ranges)} bytes, expected 24 (3 LE u64s)", source_ref)

    child_base, parent_base, size = struct.unpack("<3Q", ranges)
    expected_ranges = (0, 0x17000000, 0x08000000)
    if (child_base, parent_base, size) != expected_ranges:
        return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "FAIL", f"/arm-io/ranges is [0x{child_base:x}, 0x{parent_base:x}, 0x{size:x}], expected [0x0, 0x17000000, 0x8000000]", source_ref)

    return CheckResult("arm_io_ranges", "Arm-IO Bus Ranges and Cells", "PASS", f"#address-cells=2, #size-cells=2, ranges=[0x{child_base:x}, 0x{parent_base:x}, 0x{size:x}]", source_ref)


def check_intc_gic(root: ADTNode) -> CheckResult:
    source_ref = "ArmCpu/source/ArmCpu.cpp:205-228; first-stage-findings.md:19"
    intc = root.find_node("arm-io/intc")
    if not intc:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", "Missing /arm-io/intc node", source_ref)

    compat = intc.get_property("compatible")
    expected_compat = b"arm,gic-v3\0"
    if compat != expected_compat:
        actual_repr = compat.decode("ascii", errors="replace") if compat else "None"
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"/arm-io/intc compatible is {compat!r} ({len(compat) if compat else 0} bytes), expected exactly b'arm,gic-v3\\0' (11 bytes)", source_ref)

    reg_bytes = intc.get_property("reg")
    if not reg_bytes or len(reg_bytes) != 32:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"/arm-io/intc reg length is {len(reg_bytes) if reg_bytes else 0} bytes, expected 32 (4 LE u64s)", source_ref)

    gicd_offset, gicd_size, gicr_offset, gicr_size = struct.unpack("<4Q", reg_bytes)
    expected_reg = (0x00a00000, 0x10000, 0x00a60000, 0x100000)
    if (gicd_offset, gicd_size, gicr_offset, gicr_size) != expected_reg:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"/arm-io/intc reg is [0x{gicd_offset:x}, 0x{gicd_size:x}, 0x{gicr_offset:x}, 0x{gicr_size:x}], expected [0xa00000, 0x10000, 0xa60000, 0x100000]", source_ref)

    # Translation via /arm-io ranges
    arm_io = root.find_node("arm-io")
    ranges = arm_io.get_property("ranges") if arm_io else None
    if not ranges or len(ranges) != 24:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", "Cannot translate GIC: invalid /arm-io/ranges", source_ref)

    child_base, parent_base, bus_size = struct.unpack("<3Q", ranges)
    translated_gicd = parent_base + gicd_offset - child_base
    translated_gicr = parent_base + gicr_offset - child_base

    if translated_gicd != 0x17a00000 or gicd_size != 0x10000:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"Translated GICD is 0x{translated_gicd:x}+0x{gicd_size:x}, expected 0x17a00000+0x10000", source_ref)
    if translated_gicr != 0x17a60000 or gicr_size != 0x100000:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"Translated GICR is 0x{translated_gicr:x}+0x{gicr_size:x}, expected 0x17a60000+0x100000", source_ref)

    # Redistributor stride check
    stride_bytes = intc.get_property("redistributor-stride")
    if not stride_bytes or len(stride_bytes) != 8:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"/arm-io/intc redistributor-stride is missing or not 8 bytes (len={len(stride_bytes) if stride_bytes else 0})", source_ref)
    stride = struct.unpack("<Q", stride_bytes)[0]
    if stride != 0x20000:
        return CheckResult("intc_gic", "GICv3 Interrupt Controller", "FAIL", f"redistributor-stride is 0x{stride:x}, expected 0x20000", source_ref)

    return CheckResult("intc_gic", "GICv3 Interrupt Controller", "PASS", f"GICv3 verified: compatible 11 bytes, translated GICD=0x{translated_gicd:x}+0x{gicd_size:x}, GICR=0x{translated_gicr:x}+0x{gicr_size:x}, stride=0x{stride:x}", source_ref)


def check_forbidden_extras(root: ADTNode) -> CheckResult:
    source_ref = "AGENT_HANDOFF.zh-CN.md:457-458; first-stage-findings.md:34,37"
    forbidden_terms = ["sheng", "ufs", "gpu", "adreno", "kgsl"]
    violations = []

    def _walk(node: ADTNode, path: str) -> None:
        curr_path = f"{path}/{node.name}" if path else f"/{node.name}"
        node_name_lower = node.name.lower()
        for term in forbidden_terms:
            if term in node_name_lower:
                violations.append(f"Forbidden node '{curr_path}' matches '{term}'")

        for k, v in node.properties.items():
            k_lower = k.lower()
            for term in forbidden_terms:
                if term in k_lower:
                    violations.append(f"Forbidden property '{curr_path}/{k}' matches '{term}'")

            if k == "compatible":
                try:
                    compat_str = v.decode("utf-8", errors="replace").lower()
                    for term in forbidden_terms:
                        if term in compat_str:
                            violations.append(f"Forbidden compatible in '{curr_path}': '{compat_str}' matches '{term}'")
                except Exception:
                    pass

        for c in node.children:
            _walk(c, curr_path)

    _walk(root, "")
    if violations:
        return CheckResult("forbidden_extras", "Forbidden Extras Check", "FAIL", "; ".join(violations), source_ref)

    return CheckResult("forbidden_extras", "Forbidden Extras Check", "PASS", "No sheng-*, UFS, or GPU nodes/properties present", source_ref)


def check_memory_map_placeholders(root: ADTNode) -> CheckResult:
    source_ref = "DarwinBoot/source/DarwinBootPkg/Driver/DarwinBoot.c:219-251; first-stage-findings.md:22"
    mem_map = root.find_node("chosen/memory-map")
    if not mem_map:
        return CheckResult("memory_map_placeholders", "Memory Map Placeholders", "PASS", "No /chosen/memory-map node present (valid for initial no-RAMDisk/no-TrustCache boot)", source_ref)

    # If memory-map is present, DarwinBoot requires placeholders to be exactly 16 bytes
    for prop in ["RAMDisk", "PackedRAMDisk", "TrustCache"]:
        val = mem_map.get_property(prop)
        if val is not None and len(val) != 16:
            return CheckResult("memory_map_placeholders", "Memory Map Placeholders", "FAIL", f"/chosen/memory-map/{prop} length is {len(val)} bytes, DarwinBoot requires exactly 16", source_ref)

    return CheckResult("memory_map_placeholders", "Memory Map Placeholders", "PASS", "/chosen/memory-map placeholders (if present) are 16 bytes", source_ref)


def validate_adt_bytes(data: bytes) -> Tuple[bool, List[CheckResult], Optional[ADTNode]]:
    """Run all validation checks against raw ADT binary data."""
    results: List[CheckResult] = []

    root, parse_res = check_parse_strict(data)
    results.append(parse_res)
    if not root:
        return False, results, None

    checks = [
        check_root_name,
        check_required_nodes,
        check_nvram_proxy_props,
        check_chrp_nvram_image,
        check_random_seed,
        check_osenvironment,
        check_dram_contract,
        check_darwinboot_memory_size,
        check_cpu_topology,
        check_arm_io_ranges,
        check_intc_gic,
        check_forbidden_extras,
        check_memory_map_placeholders,
    ]

    for check_func in checks:
        results.append(check_func(root))

    overall_passed = all(r.status != "FAIL" for r in results)
    return overall_passed, results, root


def validate_adt_file(path: Path) -> Tuple[bool, List[CheckResult], Optional[ADTNode]]:
    if not path.is_file():
        res = CheckResult(
            check_id="file_exists",
            name="ADT File Exists",
            status="FAIL",
            detail=f"File not found: {path}",
            source_ref="validate_adt.py"
        )
        return False, [res], None

    try:
        data = path.read_bytes()
    except Exception as e:
        res = CheckResult(
            check_id="file_read",
            name="ADT File Read",
            status="FAIL",
            detail=f"Could not read file: {e}",
            source_ref="validate_adt.py"
        )
        return False, [res], None

    return validate_adt_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Strict host-side validator for nabu Apple Device Tree (ADT) sidecars."
    )
    parser.add_argument("adt_file", type=Path, help="Path to the .adt binary file to validate")
    parser.add_argument("--json", type=Path, dest="json_out", help="Write validation report to JSON file")
    args = parser.parse_args()

    passed, results, root = validate_adt_file(args.adt_file)

    print("=" * 80)
    print(f"NABU APPLE ADT VALIDATOR: {args.adt_file}")
    print("=" * 80)

    for r in results:
        status_marker = f"[{r.status}]"
        print(f"{status_marker:8} {r.name:<32} {r.detail}")
        print(f"         Derived from: {r.source_ref}")

    total = len(results)
    n_pass = sum(1 for r in results if r.status == "PASS")
    n_warn = sum(1 for r in results if r.status == "WARN")
    n_fail = sum(1 for r in results if r.status == "FAIL")

    print("-" * 80)
    print(f"Summary: {total} checks | {n_pass} passed | {n_warn} warnings | {n_fail} failed")
    print(f"Result:  {'OVERALL PASS' if passed else 'OVERALL FAIL'}")
    print("=" * 80)

    if root is not None:
        print("\n--- Device Tree Dump ---")
        print(root.dump())
        print("------------------------\n")

    if args.json_out:
        report = {
            "file": str(args.adt_file.resolve()),
            "passed": passed,
            "summary": {
                "total": total,
                "passed": n_pass,
                "warnings": n_warn,
                "failed": n_fail,
            },
            "checks": [
                {
                    "id": r.check_id,
                    "name": r.name,
                    "status": r.status,
                    "detail": r.detail,
                    "source_ref": r.source_ref,
                }
                for r in results
            ],
            "tree": root.to_dict() if root is not None else None,
        }
        try:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Wrote JSON report to {args.json_out}")
        except Exception as e:
            print(f"Error writing JSON report: {e}", file=sys.stderr)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
