#!/usr/bin/env python3
"""Prepare the pinned driver for bounded, opt-in raw-LUN read-only service."""
from pathlib import Path
import hashlib
import json
import re
import shutil

import prepare_nabu_ufs_source as legacy

PATCHES = ('nabu-ufs-readonly-commands.patch', 'nabu-ufs-smmu-revalidate.patch')
HEADERS = ('NabuUfsHostSafety.h', 'NabuUfsQueue.h', 'NabuUfsResources.h', 'NabuUfsService.h')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Expected one pinned UFS source anchor: ' + old[:100])
    return text.replace(old, new, 1)


def replace_function(text, signature, replacement):
    pattern = re.compile('^' + re.escape(signature) + r'\n\{.*?^\}', re.M | re.S)
    if len(pattern.findall(text)) != 1:
        raise ValueError('Expected one pinned function: ' + signature)
    return pattern.sub(lambda match: replacement, text, count=1)


SMMU_FUNCTION = '''static bool smmuBypassStream (uint16_t stream, OSSharedPtr<IOMemoryMap> &keep, uint32_t *report,
                              uint64_t dma, uint64_t bytes, const char **why)
{
  uintptr_t smmu = mapPhys(nabu_ufs::kBoard.smmuBase, nabu_ufs::kBoard.smmuBytes, keep);
  if (!smmu) { *why = "SMMU map"; return false; }
  auto read = [smmu](unsigned offset) { return read32(smmu, offset); };
  UfsSmmuPlan plan = planUfsSmmu(stream, dma, bytes, read,
                                static_cast<unsigned>(nabu_ufs::kBoard.smmuBytes));
  gRootDiagnostic.smmuId1 = read(0x24);
  gRootDiagnostic.smmuId2 = read(0x28);
  gRootDiagnostic.smmuSlot = plan.slot;
  gRootDiagnostic.smr = plan.smr;
  gRootDiagnostic.s2cr = plan.s2cr;
  // Preserve the observed route, even when planning refuses it. Inspect only
  // a valid translating group's bank within the already validated geometry.
  unsigned observedBank = plan.s2cr & 255U;
  if ((plan.smr & 0x80000000U) && ((plan.s2cr >> 16) & 3U) == 0 &&
      observedBank < plan.contextBanks && plan.pages &&
      (plan.pages + observedBank + 1U) * 4096U <= nabu_ufs::kBoard.smmuBytes) {
    gRootDiagnostic.cbar = read(0x1000 + 4 * observedBank);
    gRootDiagnostic.cba2r = read(0x1800 + 4 * observedBank);
    gRootDiagnostic.sctlr = read((plan.pages + observedBank) * 4096);
  }
  if (plan.error) {
    gRootDiagnostic.result = static_cast<uint32_t>(kIOReturnNotReady);
    *why = plan.error; return false;
  }
  const char *failure = configureUfsSmmu(plan, stream, read,
    [smmu](unsigned offset, uint32_t value) {
      write32(smmu, offset, value);
      __asm__ volatile ("dsb sy" ::: "memory");
    });
  if (failure) {
    gRootDiagnostic.result = static_cast<uint32_t>(kIOReturnNotReady);
    *why = failure; return false;
  }
  report[0] = plan.slot | (plan.bank << 16);
  report[1] = read(0x1000 + 4 * plan.bank);
  report[2] = read((plan.pages + plan.bank) * 4096);
  return true;
}'''

BRINGUP_FUNCTION = '''static bool hostBringUp (const char **why)
{
  if (!hostBeginBringup(why)) return false;
  HostPreparedDmaGuard allocation;
  gRootDiagnostic.stage = "controller map";
  gHost.hc = mapPhys(nabu_ufs::kBoard.hcBase, nabu_ufs::kBoard.hcMapBytes, gHost.hcMap);
  if (!gHost.hc) { *why = "controller map"; return false; }
  gRootDiagnostic.cap = read32(gHost.hc, 0);
  gRootDiagnostic.version = read32(gHost.hc, 8);
  if (!gRootDiagnostic.cap || gRootDiagnostic.cap == UINT32_MAX ||
      !gRootDiagnostic.version || gRootDiagnostic.version == UINT32_MAX) {
    *why = "invalid UFS controller identity"; return false;
  }
  gRootDiagnostic.stage = "DMA allocation";
  gHost.dma = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
    static_cast<IOOptionBits>(kIODirectionInOut) | static_cast<IOOptionBits>(kIOMemoryPhysicallyContiguous) |
    static_cast<IOOptionBits>(kIOMemoryMapperNone), kDmaBytes, 4096);
  gHost.lock = IOLockAlloc();
  if (!gHost.dma || !gHost.lock) { *why = "DMA/lock allocation"; return false; }
  gHost.virt = static_cast<uint8_t *>(gHost.dma->getBytesNoCopy());
  IOByteCount contiguous = 0;
  gHost.phys = gHost.dma->getPhysicalSegment(0, &contiguous, kIOMemoryMapperNone);
  gRootDiagnostic.dma = gHost.phys;
  gRootDiagnostic.contiguous = contiguous;
  if (!gHost.virt || !hostDmaRangeValid(gHost.phys, contiguous, (gRootDiagnostic.cap & 0x01000000) != 0)) {
    *why = "DMA address/contiguity"; return false;
  }
  bzero(gHost.virt, kDmaBytes);
  cacheCivac(gHost.virt, kDmaBytes);
  gRootDiagnostic.stage = "queue ownership";
  if (!hostStopQueue(why)) return false;
  uint32_t report[3] = {};
  gRootDiagnostic.stage = "SMMU plan/configure";
  if (!smmuBypassStream(nabu_ufs::kBoard.streamId, gHost.smmuMap, report, gHost.phys, kDmaBytes, why)) {
    gHost.poisoned = true; return false;
  }
  gHost.smmu = gHost.smmuMap->getVirtualAddress();
  uint32_t idr1 = read32(gHost.smmu, 0x24);
  gHost.cb = gHost.smmu + ((1U << (((idr1 >> 28) & 7) + 1)) + (report[0] >> 16)) * 4096;
  if (!hostStartQueue(why)) return false;
  gRootDiagnostic.stage = "NOP OUT";
  if (hostNop() != kIOReturnSuccess) { *why = "NOP OUT"; return false; }
  uint32_t power = 0;
  if (hostQueryRead(3, 2, &power) != kIOReturnSuccess) { *why = "power mode query"; return false; }
  gRootDiagnostic.power = power;
  // No START STOP UNIT, reset, link startup or power transition in this path.
  if ((power & 0xff) != 0x11) { *why = "firmware left UFS device inactive"; return false; }
  gRootDiagnostic.stage = "LUN ready";
  for (unsigned attempt = 0; attempt < 20; ++attempt) {
    uint8_t tur[6] = {};
    uint32_t scsi = 0;
    IOReturn status = hostScsi(0, tur, sizeof(tur), false, 0, 200000, &scsi);
    if (status == kIOReturnSuccess) {
      gRootDiagnostic.stage = "LUN capacity";
      if (hostReadCapacity4k(&gHost.blocks) != kIOReturnSuccess) {
        *why = "READ CAPACITY(10), 4K geometry required"; return false;
      }
      gHost.ready = true;
      allocation.keep = true;
      return true;
    }
    if (gHost.poisoned || status != kIOReturnNotReady || scsi != 2) break;
    IOSleep(10);
  }
  *why = "LUN 0 not ready";
  return false;
}'''


def transform(text):
    root_probe = '''  if (OSDynamicCast (IOPlatformExpertDevice, provider)) {
    // Second personality (KernelConfigTables: IOMatchCategory NativeUfsRoot): attaches to the
    // root device, which starts before the platform expert publishes IOResources, so the
    // hardware probes run before the original AMFI (whose start panics without a PMGR).
    native_ufs_matched = 1;
    if (score) {
      *score = 500;
    }
    return this;
  }'''
    text = replace_once(text, root_probe,
                        '  if (OSDynamicCast (IOPlatformExpertDevice, provider)) return nullptr;')
    text = replace_once(text, '#include "NabuBoard.h"',
                        '#include "NabuBoard.h"\n#include "NabuUfsResources.h"')
    text = replace_once(text, '  bool startRoot (IOService *provider);',
                        '  bool startRoot (IOService *provider);\n  bool startReadOnly(IOService *provider);')
    text = replace_once(text, '  bool poisoned = false;',
                        '  bool poisoned = false;\n  bool attempted = false;\n'
                        '  bool queueTouched = false, queueStopped = false, queueOwned = false;\n'
                        '  uint64_t blocks = 0;')
    text = replace_once(text, '#include "RootQueue.h"',
                        '#include "NabuUfsHostSafety.h"\n#include "NabuUfsQueue.h"')
    smmu = ('static void smmuBypassStream (uint16_t stream, OSSharedPtr<IOMemoryMap> &keep, uint32_t *report,\n'
            '                              uint64_t dma, uint64_t bytes)')
    text = replace_function(text, smmu, SMMU_FUNCTION)
    text = replace_function(text, 'static bool hostBringUp (const char **why)', BRINGUP_FUNCTION)
    text = replace_function(text, 'bool NativeUfs::start (IOService *provider)', '#include "NabuUfsService.h"')
    # Unsafe historical firmware-buffer adoption and perpetual diagnostics are
    # not an alternative entry into this artifact, even through a future caller.
    for name, argument in (('inspect', 'void'), ('dumpFirmwareList', 'void'),
                           ('inspectSmmu', 'void'), ('inspectContextBanks', 'void'),
                           ('adoptAndRead', 'unsigned level')):
        body = '(void)level;' if name == 'adoptAndRead' else ''
        signature = f'void NativeUfs::{name} ({argument})'
        text = replace_function(text, signature, signature + '\n{\n  ' + body + '\n}')
    # These helpers served only the removed firmware-buffer diagnostic.
    start = text.index('// Adopt the controller the firmware left running')
    end = text.index('// Give the UFS stream a pass-through mapping', start)
    text = text[:start] + text[end:]
    text = replace_once(text, '  const char *windowLabel () const { return label; }',
                        '  bool physicalLun = false;\n'
                        '  bool configurePhysicalLun(uint64_t capacity) {\n'
                        '    physicalLun = true; return configure("nabu-ufs-lun0", 0, capacity);\n'
                        '  }\n  const char *windowLabel () const { return label; }')
    text = replace_once(text, '*value = 512; return kIOReturnSuccess;',
                        '*value = physicalLun ? 4096 : 512; return kIOReturnSuccess;')
    text = replace_once(text, '*value = bytes / 512 - 1;', '*value = bytes / (physicalLun ? 4096 : 512) - 1;')
    text = replace_once(text, 'const_cast<char *> ("UFS LUN 0 userdata window, read-only")',
                        'const_cast<char *> (physicalLun ? "SM8150 UFS LUN 0, read-only" : "UFS readonly window")')
    text = replace_once(text,
        '  if (!buffer || !completion || !completion->action || !count || block >= bytes / 512 ||\n'
        '      count > bytes / 512 - block || buffer->getLength () < count * 512) {',
        '  uint64_t windowBlock = 0, windowCount = 0;\n'
        '  if (!buffer || !completion || !completion->action ||\n'
        '      !nabuUfsRequestGeometry(physicalLun, bytes, block, count, buffer->getLength(), windowBlock, windowCount)) {')
    text = replace_once(text, 'ufsReadWindow (operations, absolute, bytes, block, count, bounce)',
                        'ufsReadWindow (operations, absolute, bytes, windowBlock, windowCount, bounce)')
    # Only the exact board compatible, never a generic qcom controller.
    text = replace_once(text, 'nabu_ufs::kBoard.compatible) ||\n                     contains (text, data->getLength (), nabu_ufs::kBoard.compatibleFallback)',
                        'nabu_ufs::kBoard.compatible)')
    text = replace_once(text, 'nabu_ufs::kBoard.compatible) ||\n                     contains (text, string->getLength (), nabu_ufs::kBoard.compatibleFallback)',
                        'nabu_ufs::kBoard.compatible)')
    return text


def prepare(source: Path, output: Path, device: Path):
    legacy.main(['--source', str(source), '--output-dir', str(output),
                 '--patch', str(device / 'patches/nabu-nativeufs-board.patch')])
    for name in PATCHES:
        patch = device / 'patches' / name
        legacy.apply_patch(output, patch, [])
    for name in HEADERS:
        shutil.copyfile(device / 'ufs' / name, output / name)
    cpp = output / 'NativeUfs.cpp'
    cpp.write_text(transform(cpp.read_text(encoding='utf-8')), encoding='utf-8')
    (output / 'readonly-source.json').write_text(json.dumps({
        'source_commit': legacy.PINNED_COMMIT,
        'patches': {name: hashlib.sha256((device / 'patches' / name).read_bytes()).hexdigest() for name in PATCHES},
        'headers': {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in HEADERS},
        'transformer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'source_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(),
        'compiled': False, 'hardware_tested': False,
    }, indent=2) + '\n', encoding='utf-8')
