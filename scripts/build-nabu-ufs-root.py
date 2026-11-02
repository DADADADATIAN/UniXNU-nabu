#!/usr/bin/env python3
"""Build the hardware UFS root-window driver for the 21H16 owner-verified kernel.

This deliberately keeps the upstream root personality and startRoot() window
publication. It does not apply the read-only service transform, so the driver
publishes the OS/SystemOS windows rather than a whole raw LUN.

The window offsets are supplied at boot:
  native-ufs-os-lba, native-ufs-os-sectors,
  native-ufs-systemos-lba, native-ufs-systemos-sectors
LBA is in 4096-byte UFS blocks; sectors are 512-byte window sectors, matching
the owner policies exactly. Without those arguments the upstream SHNGROOT
manifest path remains available as a fallback.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

import native_ufs_bindings as bindings
import prepare_nabu_ufs_source as prepare

spec = importlib.util.spec_from_file_location(
    'nabu_ufs_platform', Path(__file__).with_name('build-nabu-platform.py'))
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)

DIRECT_FUNCTION = r'''// Boot-session direct windows: the physical layout is supplied by the loader
// instead of a SHNGROOT manifest. Returns 0 when not requested, 1 when built,
// -1 when the arguments are present but invalid (never fall back silently).
static int nabuDirectWindowLayout (RootLayout *layout, const char **why)
{
  uint32_t osLba = 0, osSectors = 0, systemLba = 0, systemSectors = 0;
  bool osSet = PE_parse_boot_argn ("native-ufs-os-lba", &osLba, sizeof (osLba));
  bool osCount = PE_parse_boot_argn ("native-ufs-os-sectors", &osSectors, sizeof (osSectors));
  bool systemSet = PE_parse_boot_argn ("native-ufs-systemos-lba", &systemLba, sizeof (systemLba));
  bool systemCount = PE_parse_boot_argn ("native-ufs-systemos-sectors", &systemSectors, sizeof (systemSectors));
  if (!osSet && !osCount && !systemSet && !systemCount) return 0;
  if (!osSet || !osCount || !systemSet || !systemCount ||
      !osLba || !osSectors || !systemLba || !systemSectors) {
    *why = "direct window boot arguments";
    return -1;
  }
  const uint64_t osOffset = uint64_t (osLba) * 4096ULL;
  const uint64_t systemOffset = uint64_t (systemLba) * 4096ULL;
  const uint64_t osBytes = uint64_t (osSectors) * 512ULL;
  const uint64_t systemBytes = uint64_t (systemSectors) * 512ULL;
  const uint64_t end = systemOffset + systemBytes;
  if ((osOffset & 4095ULL) || (systemOffset & 4095ULL) ||
      (osBytes & 511ULL) || (systemBytes & 511ULL) ||
      systemOffset <= osOffset || systemOffset < osOffset + osBytes ||
      end < systemOffset || end > (uint64_t (UINT32_MAX) + 1ULL) * 4096ULL) {
    *why = "direct window geometry";
    return -1;
  }
  bzero (layout, sizeof (*layout));
  layout->userdataFirst = osLba;
  layout->userdataLast = (end + 4095ULL) / 4096ULL - 1ULL;
  layout->imageBytes = end - osOffset;
  layout->windows = 2;
  strlcpy (layout->window[0].name, "OS", sizeof (layout->window[0].name));
  layout->window[0].offset = 0;
  layout->window[0].size = osBytes;
  strlcpy (layout->window[1].name, "SystemOS", sizeof (layout->window[1].name));
  layout->window[1].offset = systemOffset - osOffset;
  layout->window[1].size = systemBytes;
  layout->manifestStatus = 0;
  IOLog ("NABU UFS DIRECT OS lba=%u sectors=%u SystemOS lba=%u sectors=%u\n",
         osLba, osSectors, systemLba, systemSectors);
  return 1;
}

'''

ROOT_READ_TIMEOUT_US = 5000000

START_ROOT = "// Boot the root image's windows as block devices. Soft-fails (logs, publishes nothing).\nbool NativeUfs::startRoot (IOService *provider)\n"
LAYOUT_LINE = '  if (!layout || !findRootLayout (layout, &why)) {\n'
DIRECT_LINE = ('  int direct = layout ? nabuDirectWindowLayout (layout, &why) : 0;\n'
               '  if (!layout || direct < 0 || (direct == 0 && !findRootLayout (layout, &why))) {\n')

BUSY_HELPER_ANCHOR = '#include "RootTransportLayout.h"\n'
BUSY_HELPER = '''
static void nabuBusyWaitUs (uint32_t usec)
{
  uint64_t deadline = 0;
  uint64_t maxSpins = uint64_t (usec) * 1000ULL;
  if (maxSpins > 2000000ULL) maxSpins = 2000000ULL;
  clock_interval_to_deadline (usec, kMicrosecondScale, &deadline);
  for (uint64_t spins = 0; spins < maxSpins; ++spins) {
    if (mach_absolute_time () >= deadline) break;
    __asm__ __volatile__ ("yield");
  }
}

static void nabuCooperativeYield (void)
{
  for (unsigned i = 0; i < 1000; ++i) {
    // XNU's zero interval leaves priority depressed without a recovery timer.
    thread_yield_internal (1);
  }
}
'''


def add_busy_helper(text):
    if text.count(BUSY_HELPER_ANCHOR) != 1:
        raise ValueError('Expected one RootTransportLayout include anchor')
    return text.replace(BUSY_HELPER_ANCHOR, BUSY_HELPER_ANCHOR + BUSY_HELPER, 1)


def add_stage_trace(text):
    pattern = re.compile(r'(\n  gRootDiagnostic\.stage = ("[^"]+");\n)')
    return pattern.sub(lambda m: m.group(1) + '  IOLog ("NABU UFS TRACE %s\\n", ' + m.group(2) + ');\n', text)


def use_busy_delays(text):
    # The early UFS bring-up runs before a working timer interrupt is proven
    # (the V5 console showed gic=0 timer=0). IOSleep waits on a timeout wake
    # that may never arrive; IODelay can still block in the same path, so use
    # an explicit counter-bounded yield loop for the two early delays.
    # The media-publication wait is different: it runs after BSD init and must
    # yield the single CPU so IOBlockStorageDriver/APFS can publish the volume.
    for old, new in (
            ('    IOSleep (50);\n', '    nabuBusyWaitUs (50000);\n'),
            ('    IOSleep (10);\n', '    nabuBusyWaitUs (10000);\n')):
        if text.count(old) != 1:
            raise ValueError('Expected one root-path delay: ' + old.strip())
        text = text.replace(old, new, 1)
    return text


def patch_root_headers(source):
    """Make the root transport poll terminate even without timer interrupts."""
    def patch(name, pairs):
        path = source / name
        text = path.read_text(encoding='utf-8')
        for old, new in pairs:
            if text.count(old) != 1:
                raise ValueError('Expected one ' + name + ' anchor: ' + old[:70])
            text = text.replace(old, new, 1)
        path.write_text(text, encoding='utf-8')

    patch('TransferPoll.h', [
        ('static constexpr uint32_t kUfsFatalStatus = 0x71880U;\n',
         'static constexpr uint32_t kUfsFatalStatus = 0x71880U;\n'
         'static constexpr uint32_t kUfsMaxPolls = 4000000U;\n'),
        ('    ++state.polls;\n',
         '    ++state.polls;\n'
         '    if (state.polls >= kUfsMaxPolls) return UfsTransferEnd::Timeout;\n'),
    ])
    commands = source / 'RootCommands.h'
    commands_text = commands.read_text(encoding='utf-8')
    commands_text = patch_root_read_timeout(commands_text)
    commands.write_text(commands_text, encoding='utf-8')

    patch('RootCommands.h', [
        ('  void delay () { IODelay (2); }\n',
         '  void delay () { nabuBusyWaitUs (2); }\n'),
        ('static IOReturn hostNop (void)\n{\n',
         'static IOReturn hostNop (void)\n{\n  IOLog ("NABU UFS NOP enter\\n");\n'),
        ('  UfsTransferEnd end = pollUfsTransfer (port, state);\n',
         '  UfsTransferEnd end = pollUfsTransfer (port, state);\n'
         '  if (gRootDiagnostic.command <= 12 || end != UfsTransferEnd::Completed) {\n'
         '    IOLog ("NABU UFS POLL command=%u end=%u polls=%u ocs=%u db=%u is=%u\\n",\n'
         '           gRootDiagnostic.command, (unsigned)end, state.polls, state.ocs,\n'
         '           state.doorbellSeen, state.interruptSeen);\n'
         '  }\n'),
    ])
    patch('RootQueue.h', [
        ('  uint64_t deadline;\n'
         '  clock_interval_to_deadline (100, kMillisecondScale, &deadline);\n'
         '  do {\n'
         '    if ((read32 (gHost.hc, offset) & mask) == value) return true;\n'
         '    IODelay (10);\n'
         '  } while (mach_absolute_time () < deadline);\n'
         '  return false;\n',
         '  for (unsigned spins = 0; spins < 20000; ++spins) {\n'
         '    if ((read32 (gHost.hc, offset) & mask) == value) return true;\n'
         '    nabuBusyWaitUs (10);\n'
         '  }\n'
         '  return false;\n'),
    ])


def patch_root_read_timeout(text):
    """Extend only the bounded READ(10) timeout; no retry or queue reset."""
    old = ('  IOReturn status = hostScsi (lun, cdb, 10, true, blocks * 4096U, 1000000, &scsi);\n')
    new = ('  IOReturn status = hostScsi (lun, cdb, 10, true, blocks * 4096U, '
           f'{ROOT_READ_TIMEOUT_US}, &scsi);\n')
    if text.count(old) != 1:
        raise ValueError('Expected one root READ(10) timeout')
    return text.replace(old, new, 1)


def add_iobsd_wait(text):
    # IOStorageFamily/IOGUIDPartitionScheme only attach after the IOBSD resource
    # is published. Root windows published before that get no IOMedia and the
    # SystemOS UUID never appears. Delay the publisher thread, not startRoot().
    old = 'static void publishThread (void *, wait_result_t)\n{\n  struct Operations {\n'
    new = ('static void publishThread (void *, wait_result_t)\n{\n'
           '  unsigned bsdTick = 0;\n'
           '  IOService *resources = IOService::getResourceService ();\n'
           '  IOLog ("NABU UFS IOBSD wait begin\\n");\n'
           '  for (; bsdTick <= 300; ++bsdTick) {\n'
           '    if (resources && resources->getProperty ("IOBSD")) break;\n'
           '    if ((bsdTick % 50) == 0) IOLog ("NABU UFS IOBSD wait tick=%u present=0\\n", bsdTick);\n'
           '    nabuCooperativeYield ();\n'
           '  }\n'
           '  IOLog ("NABU UFS IOBSD wait tick=%u present=%u\\n", bsdTick,\n'
           '         (resources && resources->getProperty ("IOBSD")) ? 1U : 0U);\n'
           '  struct Operations {\n')
    if text.count(old) != 1:
        raise ValueError('Expected the publishThread anchor')
    return text.replace(old, new, 1)


def add_device_type(text):
    # IOBlockStorageDriver matches IOBlockStorageDevice services whose
    # "device-type" is Generic. The manually created UFS window services do not
    # come from an Info.plist personality, so state the property explicitly.
    old = '  strlcpy (label, name, sizeof (label));\n'
    new = ('  strlcpy (label, name, sizeof (label));\n'
           '  setProperty ("device-type", "Generic");\n')
    if text.count(old) != 1:
        raise ValueError('Expected the NativeUfsBlock configure anchor')
    return text.replace(old, new, 1)


def use_cooperative_media_wait(text):
    old = ('      for (unsigned tick = 0; tick <= 300; ++tick) {\n'
           '        ready = mediaWithUuidExists (uuid, device);\n'
           '        if (ready || tick == 300) break;\n'
           '        IOSleep (100);\n'
           '      }\n')
    new = ('      for (unsigned tick = 0; tick <= 300; ++tick) {\n'
           '        ready = mediaWithUuidExists (uuid, device);\n'
           '        if (ready || tick == 300) break;\n'
           '        nabuCooperativeYield ();\n'
           '      }\n')
    if text.count(old) != 1:
        raise ValueError('Expected the publisher media wait anchor')
    return text.replace(old, new, 1)


def transform(text):
    if text.count(START_ROOT) != 1:
        raise ValueError('Expected the pinned NativeUfs startRoot anchor')
    start = text.index(START_ROOT)
    if LAYOUT_LINE not in text[start:]:
        raise ValueError('Expected the startRoot layout line')
    text = text.replace(START_ROOT, DIRECT_FUNCTION + START_ROOT, 1)
    start = text.index(START_ROOT)
    at = text.index(LAYOUT_LINE, start)
    text = text[:at] + DIRECT_LINE + text[at + len(LAYOUT_LINE):]
    text = use_busy_delays(add_device_type(add_iobsd_wait(add_stage_trace(add_busy_helper(text)))))
    return use_cooperative_media_wait(text)


def main():
    root = Path(__file__).resolve().parents[1]
    device = Path(os.environ['UNIXNU_DEVICE']).resolve()
    if os.environ.get('XNU_OWNER_ROOT_TRUST', '0') != '1':
        raise SystemExit('The UFS root windows require owner root trust')
    if os.environ.get('XNU_NATIVE_UFS', '0') != '1':
        raise SystemExit('This archive is only built for the UFS profile')
    if os.environ.get('NABU_UFS_READONLY', '0') == '1':
        raise SystemExit('The read-only service cannot publish verified root windows')

    recipe_path = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe_path.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    headers = root / 'build/storage-abi/include'
    if not (headers / 'IOKit/storage/IOBlockStorageDevice.h').is_file():
        raise SystemExit('The UFS class requires the prepared IOStorageFamily headers')

    out = root / 'build/native-ufs'
    if out.exists():
        raise SystemExit('Refuse an existing UFS output; use a fresh build tree')
    source = out / 'source'
    prepare.main(['--source', str((root / 'drivers/NativeUfs').resolve()),
                  '--output-dir', str(source),
                  '--patch', str(device / 'patches/nabu-nativeufs-board.patch')])
    prepare.apply_patch(source, device / 'patches/nabu-ufs-smmu-revalidate.patch', [])

    cpp = source / 'NativeUfs.cpp'
    cpp.write_text(transform(cpp.read_text(encoding='utf-8')), encoding='utf-8')
    patch_root_headers(source)
    logging = os.environ.get('NABU_CAPTURE_LOG') == '1'
    logging_identity = None
    if logging:
        text = cpp.read_text(encoding='utf-8')
        anchors = [
            ('struct UfsHost {\n', 'static uint64_t nabu_log_lun_blocks;\n\nstruct UfsHost {\n'),
            ('      gHost.ready = true;\n',
             '      nabu_log_lun_blocks = uint64_t(loadBe32(gHost.virt + kDataOffset)) + 1;\n'
             '      gHost.ready = true;\n'),
            (START_ROOT, '#include "NabuLogUfs.h"\n\n' + START_ROOT),
            ('  native_ufs_root_step = 2;\n', '  nabuLogStart();\n  native_ufs_root_step = 2;\n'),
        ]
        for old, new in anchors:
            if text.count(old) != 1:
                raise ValueError('Unexpected log integration anchor: ' + old)
            text = text.replace(old, new, 1)
        cpp.write_text(text, encoding='utf-8')
        identity = hashlib.sha256()
        for header in sorted((device / 'ufs').glob('NabuLog*.h')):
            content = header.read_bytes()
            (source / header.name).write_bytes(content)
            identity.update(header.name.encode() + b'\0' + content)
        identity.update(b'nabu_capture_source.py\0' + (device / 'scripts/nabu_capture_source.py').read_bytes())
        identity.update(b'NabuHeartbeat.cpp\0' + (device / 'platform/NabuHeartbeat.cpp').read_bytes())
        logging_identity = identity.hexdigest()
        (source / 'NabuLogBuild.h').write_text(
            'static const unsigned char nabu_log_build_id[32] = {' +
            ','.join(str(b) for b in identity.digest()) + '};\n', encoding='utf-8')
    obj = out / 'NativeUfs.o'
    command = platform.compile_command(record, cpp, obj)
    command += ['-I', str(headers), '-I', str(root / '.cache/xnu-work/osfmk'),
                '-I', str(root / 'drivers/NativeVirtioBlock'),
                '-I', str(root / 'kits/VerifiedRoot/include'),
                '-DNATIVE_VERIFIED_BLOCK=1',
                '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1',
                '-DXNU_NATIVE_UFS=1']
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if recipe_path.read_bytes() != recipe_bytes:
        raise SystemExit('UFS compilation modified the original XNU recipe')
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    platform.check_object(obj.read_bytes())
    bindings.qualify_object(bindings.MachO(obj))

    # VirtIO's original-bindings.o is the single provider of the absolute
    # IOBlockStorageDevice aliases in this combined profile. Keep the UFS
    # archive free of a duplicate binding object and let force_load resolve
    # the imports from the VirtIO archive.
    #
    # BootProgress is disabled in this profile, so its optional observer has no
    # kernel definition. A weak no-op keeps the verified read path linkable and
    # is discarded if a profile later provides the real poll.
    compat = out / 'UfsRootCompat.cpp'
    compat.write_text('extern "C" __attribute__((weak)) void boot_progress_poll (void) {}\n',
                      encoding='utf-8')
    compat_obj = out / 'UfsRootCompat.o'
    compat_command = platform.compile_command(record, compat, compat_obj)
    result = subprocess.run(compat_command, cwd=record['directory'], capture_output=True)
    (out / 'compat-compile.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    platform.check_object(compat_obj.read_bytes())

    archive = out / 'libNativeUfs.a'
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj), str(compat_obj)], check=True)
    (out / 'build-report.json').write_text(json.dumps({
        'source_commit': prepare.PINNED_COMMIT,
        'source_files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(source.iterdir()) if p.suffix in ('.cpp', '.h')},
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
        'source_flags': ['-DNATIVE_VERIFIED_BLOCK=1', '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1'],
        'bindings': {n: hex(v) for n, v in bindings.BINDINGS.items()},
        'direct_windows': True, 'verified_root_enabled': True,
        'readonly_service': False, 'compiled': True, 'linked': False,
        'log_capture': logging, 'log_persistence_default': 'off',
        'logging_source_identity': logging_identity,
        'hardware_tested': False, 'runtime_qualified': False,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
