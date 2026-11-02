#!/usr/bin/env python3
"""Unit tests for the small APFS fixture contract; no image or guest is created."""
from __future__ import annotations

import copy
import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import apfs_fixture


class FixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def image(self, size=apfs_fixture.MIN_IMAGE_BYTES):
        path = self.root / "fixture.raw"
        data = bytearray(size)
        data[32:36] = b"NXSB"
        struct.pack_into("<IQ", data, 36, 4096, size // 4096)
        path.write_bytes(data)
        return path, {
            "format": "raw",
            "encrypted": False,
            "single_volume": True,
            "probe_path": "/probe.bin",
            "probe_sha256": apfs_fixture.PROBE_SHA256,
            "probe_size": len(apfs_fixture.PROBE_CONTENT),
            "image_bytes": size,
            "image_sha256": hashlib.sha256(data).hexdigest(),
        }

    def test_accepts_minimum_raw_fixture(self):
        path, metadata = self.image()
        apfs_fixture.validate_host_metadata(metadata, path)

    def test_rejects_encryption(self):
        path, metadata = self.image()
        metadata["encrypted"] = True
        with self.assertRaises(apfs_fixture.FixtureError):
            apfs_fixture.validate_host_metadata(metadata, path)

    def test_rejects_more_than_64_mib(self):
        path, metadata = self.image()
        metadata["image_bytes"] += apfs_fixture.PAGE_BYTES
        with self.assertRaises(apfs_fixture.FixtureError):
            apfs_fixture.validate_host_metadata(metadata, path)

    def test_rejects_probe_hash_substitution(self):
        path, metadata = self.image()
        metadata["probe_sha256"] = hashlib.sha256(b"wrong").hexdigest()
        with self.assertRaises(apfs_fixture.FixtureError):
            apfs_fixture.validate_host_metadata(metadata, path)

    def test_rejects_non_apfs_magic(self):
        path, metadata = self.image()
        data = bytearray(path.read_bytes())
        data[32:36] = b"HFSX"
        path.write_bytes(data)
        metadata["image_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(apfs_fixture.FixtureError):
            apfs_fixture.validate_host_metadata(metadata, path)

    def test_creation_fails_closed_off_macos(self):
        with mock.patch.object(apfs_fixture.sys, "platform", "linux"):
            with self.assertRaisesRegex(apfs_fixture.FixtureError, "macOS"):
                apfs_fixture.build_fixture(self.root / "out")

    def test_creation_refuses_nonempty_output(self):
        output = self.root / "out"
        output.mkdir()
        (output / "keep").write_text("do not overwrite", encoding="utf-8")
        with mock.patch.object(apfs_fixture.sys, "platform", "darwin"):
            with self.assertRaisesRegex(apfs_fixture.FixtureError, "absent or empty"):
                apfs_fixture.build_fixture(output)
        self.assertEqual((output / "keep").read_text(encoding="utf-8"), "do not overwrite")



if __name__ == "__main__":
    unittest.main()
