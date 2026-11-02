"""Focused tests for inspect_ipsw.py: synthetic ZIP, directory mode, rejection
gates, caps and no-overwrite rules. In-memory or approved Temp only."""
import io
import json
import plistlib
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import inspect_ipsw  # noqa: E402


def temp_dir():
    return Path(tempfile.mkdtemp(prefix='ipados17-inspect-'))


def make_plist(version='17.6.1', build='21G101', types=('iPad7,3',)):
    return plistlib.dumps({
        'ProductVersion': version, 'ProductBuildVersion': build,
        'SupportedProductTypes': list(types),
        'BuildIdentities': [{'ApBoardId': '0x06', 'ApChipID': '0x8010',
                             'ApProductType': types[0],
                             'Info': {'DeviceClass': 'j127ap'},
                             'Manifest': {'KernelCache': {'Info': {'Path': 'kernelcache.release.ipad7'}},
                                          'OS': {'Info': {'Path': '044-00000.dmg'}}}}],
    })


def make_zip_bytes(plist, extra_kernel=True):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('BuildManifest.plist', plist)
        if extra_kernel:
            archive.writestr('kernelcache.release.ipad7', b'\xcf\xfa\xed\xfe' + b'\0' * 64)
    return buffer.getvalue()


class InspectIpswTests(unittest.TestCase):
    def run_cli(self, *argv):
        code = inspect_ipsw.main(list(argv))
        return code

    def setUp(self):
        self.dir = temp_dir()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_synthetic_zip_ok(self):
        ipsw = self.dir / 'sample.ipsw'
        ipsw.write_bytes(make_zip_bytes(make_plist()))
        out = self.dir / 'report.json'
        code = self.run_cli(str(ipsw), '--output', str(out))
        self.assertEqual(0, code)
        report = json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(17, int(report['version_gate']['actual_values']
                                 ['ProductVersion'].split('.')[0]))
        self.assertTrue(report['version_gate']['accepted'])
        self.assertEqual('kernelcache.release.ipad7',
                         report['build_manifest']['build_identities'][0]['KernelCachePath'])
        self.assertFalse(report['status']['kernelcache_extracted'])
        names = {item['name'] for item in report['notable_members']}
        self.assertIn('kernelcache.release.ipad7', names)

    def test_directory_mode_ok(self):
        root = self.dir / 'unpacked'
        root.mkdir()
        (root / 'BuildManifest.plist').write_bytes(make_plist())
        (root / '044-00000.dmg').write_bytes(b'dmg-bytes')
        out = self.dir / 'dir-report.json'
        code = self.run_cli(str(root), '--output', str(out))
        self.assertEqual(0, code)
        report = json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(report['input']['mode'], 'directory')
        self.assertEqual(report['build_manifest']['ProductVersion'], '17.6.1')

    def test_wrong_major_version_rejected(self):
        ipsw = self.dir / 'old.ipsw'
        ipsw.write_bytes(make_zip_bytes(make_plist(version='16.7.10')))
        out = self.dir / 'old-report.json'
        self.assertEqual(1, self.run_cli(str(ipsw), '--output', str(out)))
        report = json.loads(out.read_text(encoding='utf-8'))
        self.assertFalse(report['version_gate']['accepted'])
        self.assertFalse(report['version_gate']['is_ios17'])
        self.assertEqual('16.7.10', report['version_gate']['actual_values']['ProductVersion'])

    def test_no_ipad_support_rejected(self):
        ipsw = self.dir / 'phone.ipsw'
        ipsw.write_bytes(make_zip_bytes(make_plist(types=('iPhone14,2',))))
        self.assertEqual(1, self.run_cli(str(ipsw), '--output', str(self.dir / 'x.json')))

    def test_other_17x_accepted_without_hardcoded_build(self):
        ipsw = self.dir / 'other.ipsw'
        ipsw.write_bytes(make_zip_bytes(make_plist(version='17.5.1', build='21F90',
                                                   types=('iPad13,18',))))
        self.assertEqual(0, self.run_cli(str(ipsw), '--output', str(self.dir / 'y.json')))

    def test_duplicate_manifest_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED) as archive:
            archive.writestr('BuildManifest.plist', make_plist())
            archive.writestr('buildmanifest.plist', make_plist())
        ipsw = self.dir / 'dup.ipsw'
        ipsw.write_bytes(buffer.getvalue())
        with self.assertRaises(inspect_ipsw.InspectError):
            inspect_ipsw.inspect_archive(ipsw)
        out = self.dir / 'dup-report.json'
        self.assertEqual(2, self.run_cli(str(ipsw), '--output', str(out)))
        self.assertFalse(out.exists())

    def test_oversized_member_rejected(self):
        huge = inspect_ipsw.PLIST_CAP + 1
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo('BuildManifest.plist')
            info.file_size = huge
            archive.writestr(info, b'\0' * huge)
        ipsw = self.dir / 'big.ipsw'
        ipsw.write_bytes(buffer.getvalue())
        with self.assertRaises(inspect_ipsw.InspectError):
            inspect_ipsw.inspect_archive(ipsw)

    def test_missing_manifest_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('other.txt', b'x')
        ipsw = self.dir / 'empty.ipsw'
        ipsw.write_bytes(buffer.getvalue())
        with self.assertRaises(inspect_ipsw.InspectError):
            inspect_ipsw.inspect_archive(ipsw)

    def test_no_overwrite_of_input_or_existing_output(self):
        ipsw = self.dir / 'sample.ipsw'
        ipsw.write_bytes(make_zip_bytes(make_plist()))
        existing = self.dir / 'exists.json'
        existing.write_text('keep me', encoding='utf-8')
        with self.assertRaises(inspect_ipsw.InspectError):
            self.run_cli(str(ipsw), '--output', str(existing))
        self.assertEqual('keep me', existing.read_text(encoding='utf-8'))
        with self.assertRaises(inspect_ipsw.InspectError):
            self.run_cli(str(ipsw), '--output', str(ipsw))
        self.assertTrue(ipsw.read_bytes()[:4].startswith(b'PK'))
        with self.assertRaises(inspect_ipsw.InspectError):
            self.run_cli(str(self.dir / 'missing.ipsw'), '--output', str(self.dir / 'z.json'))


if __name__ == '__main__':
    unittest.main()
