"""The mdev preparer must consume a real, internally consistent image report."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import prepare_mdev_probe
from prepare_mdev_probe import prepare


class PrepareMdevProbe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        self.image = self.root / "image.raw"
        image = bytearray(4096)
        image[32:36] = b"NXSB"
        struct.pack_into("<IQ", image, 36, 4096, 1)
        self.image.write_bytes(image)
        (self.fixture / "launchd.macho").write_bytes(b"\xcf\xfa\xed\xfe" + bytes(28))
        (self.fixture / "addresses.json").write_text("{}\n", encoding="utf-8")
        (self.fixture / "el0-contract.json").write_text(json.dumps({
            "mdev_block_read_probe": True,
            "mdev_device": "/dev/md1",
            "buffers": {"preserved": {"size": 1, "sha256": "0" * 64}},
        }), encoding="utf-8")
        self.report = self.root / "apfs-probe.json"
        self.metadata = {
            "format": "raw", "creation_passed": True, "encrypted": False,
            "single_volume": True, "probe_path": "/probe.bin",
            "probe_sha256": hashlib.sha256(b"HACKIOS_APFS_PROBE_V1\n").hexdigest(),
            "probe_size": 22, "image_bytes": len(image),
            "image_sha256": hashlib.sha256(image).hexdigest(),
        }
        self.write_report()

    def write_report(self):
        self.report.write_text(json.dumps(self.metadata), encoding="utf-8")

    def test_accepts_created_and_validated_fixture(self):
        receipt = prepare(self.fixture, self.image, self.report, self.root / "out")
        contract = json.loads((self.root / "out/el0-contract.json").read_text(encoding="utf-8"))
        self.assertIn("preserved", contract["buffers"])
        self.assertIn("_md1_buffer", contract["buffers"])
        self.assertEqual(receipt["image_sha256"], self.metadata["image_sha256"])

    def test_rejects_report_without_creation_proof(self):
        for value in (None, False):
            with self.subTest(value=value):
                if value is None:
                    self.metadata.pop("creation_passed", None)
                else:
                    self.metadata["creation_passed"] = value
                self.write_report()
                output = self.root / ("out-" + str(value))
                with self.assertRaisesRegex(ValueError, "successful fixture creation"):
                    prepare(self.fixture, self.image, self.report, output)
                self.assertFalse(output.exists())

    def test_rejects_image_swapped_after_report_validation(self):
        original = self.image.read_bytes()

        def swap_after_validation(*_args):
            changed = bytearray(original)
            changed[-1] ^= 1
            self.image.write_bytes(changed)
            return self.metadata

        output = self.root / "out-swapped"
        with mock.patch.object(prepare_mdev_probe, "load_report",
                               side_effect=swap_after_validation):
            with self.assertRaisesRegex(ValueError, "changed after metadata validation"):
                prepare(self.fixture, self.image, self.report, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
