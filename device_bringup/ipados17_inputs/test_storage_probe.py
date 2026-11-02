"""Storage cases must be bound to the fixture, payload and boot configuration."""
import copy
import hashlib
import unittest
from run_storage_probe import (expected_refusal, expected_success, md1_boot_configuration,
                               validate_fixture_case)


IMAGE_BYTES = 0x100000
IMAGE_OFFSET = 0x1000
IMAGE_SHA256 = "1" * 64
FIRST_SHA256 = "2" * 64


def fixture_contract():
    return {
        "mdev_block_read_probe": True,
        "mdev_device": "/dev/md1",
        "mdev_read_offset": 0,
        "mdev_write_open": False,
        "mdev_image_offset": IMAGE_OFFSET,
        "mdev_image_bytes": IMAGE_BYTES,
        "mdev_image_sha256": IMAGE_SHA256,
        "buffers": {"_md1_buffer": {"size": 4096, "sha256": FIRST_SHA256}},
    }


def payload():
    return {
        "image_offset": IMAGE_OFFSET,
        "image_bytes": IMAGE_BYTES,
        "image_sha256": IMAGE_SHA256,
    }


class RefusalEvidence(unittest.TestCase):
    def report(self, case):
        size = IMAGE_BYTES + (4096 if case == "wrong-capacity" else 0)
        boot = "-v serial=3 debug=0x14e rd=md0"
        if case != "no-device":
            boot += (f" hackios-apfs-md1=1 hackios-apfs-md1-offset={IMAGE_OFFSET:#x}"
                     f" hackios-apfs-md1-size={size:#x}")
        return {"passed": False, "gdb_globals": {
            "_panicstr": 0, "_md1_open_flags": 0x20000000,
            "_mdev_apfs_md1_reads": 0,
            "_mdev_apfs_md1_ready": 1 if case == "write-open" else 0,
            "_md1_open_result": 30 if case == "write-open" else 2,
            "_mdev_apfs_md1_status": (22 if case == "wrong-capacity"
                                      else 0 if case == "write-open" else -1),
            "_mdev_apfs_md1_capacity_bytes": IMAGE_BYTES if case == "write-open" else 0,
            "_mdev_apfs_md1_writes": 1, "_mdev_apfs_md1_write_failures": 1,
        }, "el0_contract": {
            "mdev_image_offset": IMAGE_OFFSET, "mdev_image_bytes": IMAGE_BYTES,
        }, "boot_args": boot}

    def test_expected_errors_are_accepted(self):
        for case in ("no-device", "wrong-capacity", "write-open"):
            with self.subTest(case=case):
                self.assertTrue(expected_refusal(self.report(case), case))

    def test_success_or_panic_is_never_an_expected_refusal(self):
        for case in ("no-device", "wrong-capacity", "write-open"):
            for field, wrong in (("passed", True), ("_panicstr", 1), ("_md1_open_result", 0),
                                 ("_md1_open_flags", 0), ("_mdev_apfs_md1_reads", 1)):
                with self.subTest(case=case, field=field):
                    report = copy.deepcopy(self.report(case))
                    target = report if field == "passed" else report["gdb_globals"]
                    target[field] = wrong
                    self.assertFalse(expected_refusal(report, case))

    def test_refusal_requires_the_case_specific_boot_capacity(self):
        for case in ("wrong-capacity", "write-open"):
            with self.subTest(case=case):
                report = copy.deepcopy(self.report(case))
                size = IMAGE_BYTES if case == "wrong-capacity" else IMAGE_BYTES + 4096
                report["boot_args"] += f" hackios-apfs-md1-size={size:#x}"
                self.assertFalse(expected_refusal(report, case))

    def test_no_device_rejects_any_md1_registration_token(self):
        report = self.report("no-device")
        report["boot_args"] += " hackios-apfs-md1=0"
        self.assertFalse(expected_refusal(report, "no-device"))


class CaseBinding(unittest.TestCase):
    def ramdisk(self, image=b"\x01" * IMAGE_BYTES):
        return bytes(IMAGE_OFFSET) + image

    def test_boot_configuration_requires_one_complete_registration(self):
        valid = ("rd=md0 hackios-apfs-md1=1 hackios-apfs-md1-offset=0x1000 "
                 "hackios-apfs-md1-size=0x100000")
        self.assertEqual(md1_boot_configuration(valid), {"offset": 0x1000, "size": 0x100000})
        for malformed in (
                "rd=md0",
                "hackios-apfs-md1=1 hackios-apfs-md1-offset=0x1000",
                valid + " hackios-apfs-md1-size=0x200000",
                "hackios-apfs-md1=0 " + valid,
                valid + " hackios-apfs-md1=1",
                valid + " hackios-apfs-md1=0",
                "hackios-apfs-md1=1 hackios-apfs-md1-offset=0x1001 "
                "hackios-apfs-md1-size=0x100000"):
            with self.subTest(arguments=malformed):
                self.assertIsNone(md1_boot_configuration(malformed))

    def test_binds_payload_trailer_contract_and_case(self):
        contract = fixture_contract()
        image = b"\x01" * IMAGE_BYTES
        contract["buffers"]["_md1_buffer"]["sha256"] = hashlib.sha256(image[:4096]).hexdigest()
        metadata = payload()
        metadata["image_sha256"] = hashlib.sha256(image).hexdigest()
        contract["mdev_image_sha256"] = metadata["image_sha256"]
        validate_fixture_case(contract, metadata, self.ramdisk(image), "block-read")

    def test_rejects_apfs_fixture_for_block_read_case(self):
        contract = fixture_contract()
        contract["apfs_file_read_probe"] = True
        with self.assertRaisesRegex(ValueError, "non-APFS"):
            validate_fixture_case(contract, payload(), self.ramdisk(), "block-read")

    def test_rejects_metadata_or_embedded_image_mismatch(self):
        contract = fixture_contract()
        metadata = payload()
        metadata["image_sha256"] = "3" * 64
        with self.assertRaisesRegex(ValueError, "metadata differ"):
            validate_fixture_case(contract, metadata, self.ramdisk(), "block-read")
        bad_contract = copy.deepcopy(contract)
        bad_contract["mdev_image_offset"] += 4096
        with self.assertRaisesRegex(ValueError, "metadata differ"):
            validate_fixture_case(bad_contract, payload(), self.ramdisk(), "block-read")
        with self.assertRaisesRegex(ValueError, "embedded APFS image"):
            validate_fixture_case(contract, payload(), self.ramdisk(), "block-read")

    def test_write_open_requires_explicit_matching_fixture(self):
        contract = fixture_contract()
        with self.assertRaisesRegex(ValueError, "write-open"):
            validate_fixture_case(contract, payload(), self.ramdisk(), "write-open")
        contract["mdev_write_open"] = True
        with self.assertRaisesRegex(ValueError, "write-open"):
            validate_fixture_case(contract, payload(), self.ramdisk(), "block-read")

    def test_block_read_requires_block_zero_and_strict_write_flag(self):
        for offset in (4096, "0", False):
            with self.subTest(offset=offset):
                contract = fixture_contract()
                contract["mdev_read_offset"] = offset
                with self.assertRaisesRegex(ValueError, "block-0"):
                    validate_fixture_case(contract, payload(), self.ramdisk(), "block-read")
        for value in (0, 1, "false", None):
            with self.subTest(write_open=value):
                contract = fixture_contract()
                contract["mdev_write_open"] = value
                with self.assertRaisesRegex(ValueError, "explicit boolean"):
                    validate_fixture_case(contract, payload(), self.ramdisk(), "block-read")
        image = b"\x01" * IMAGE_BYTES
        contract = fixture_contract()
        contract["buffers"]["_md1_buffer"]["sha256"] = hashlib.sha256(image[:4096]).hexdigest()
        metadata = payload()
        metadata["image_sha256"] = hashlib.sha256(image).hexdigest()
        contract["mdev_image_sha256"] = metadata["image_sha256"]
        contract.pop("mdev_write_open")
        validate_fixture_case(contract, metadata, self.ramdisk(image), "block-read")

    def test_baseline_rejects_storage_fixture(self):
        with self.assertRaisesRegex(ValueError, "baseline"):
            validate_fixture_case(fixture_contract(), None, None, "baseline")


class PositiveEvidence(unittest.TestCase):
    def test_apfs_file_requires_explicit_mount_and_read_pass(self):
        report = {"passed": True, "apfs_mount_tested": True,
                  "apfs_readonly_file_test_passed": True}
        self.assertTrue(expected_success(report, "apfs-file"))
        for field in ("apfs_mount_tested", "apfs_readonly_file_test_passed"):
            with self.subTest(field=field):
                missing = copy.deepcopy(report)
                missing[field] = False
                self.assertFalse(expected_success(missing, "apfs-file"))

    def test_block_read_does_not_claim_apfs_success(self):
        self.assertFalse(expected_success({"passed": False}, "block-read"))
        self.assertTrue(expected_success({"passed": True}, "block-read"))

    def test_retained_apfs_failure_is_not_treated_as_success(self):
        report = {
            "passed": False, "apfs_mount_tested": True,
            "apfs_readonly_file_test_passed": False,
        }
        self.assertFalse(expected_success(report, "apfs-file"))


if __name__ == "__main__":
    unittest.main()
