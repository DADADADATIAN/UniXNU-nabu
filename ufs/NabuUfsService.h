// SPDX-License-Identifier: BSD-2-Clause-Patent
// Included after NativeUfsBlock and the transport. No old probe mode can select
// this service; only the explicit read-only option and exact provider contract.
#if !defined(NABU_UFS_READONLY) || NABU_UFS_READONLY != 1
#error "This prepared artifact requires the nabu read-only UFS build"
#endif
#if !defined(NATIVE_VERIFIED_BLOCK) || NATIVE_VERIFIED_BLOCK != 0
#error "The raw read-only LUN is not an owner-verified root device"
#endif

extern "C" {
volatile uint32_t native_ufs_readonly_abi = 1;
volatile uint32_t native_ufs_readonly_starts = 0;
volatile uint32_t native_ufs_readonly_requested = 0;
volatile uint32_t native_ufs_readonly_stage = 0;
volatile uint32_t native_ufs_readonly_gdsc = 0;
volatile uint32_t native_ufs_readonly_axi = 0;
volatile uint32_t native_ufs_readonly_ahb = 0;
volatile uint64_t native_ufs_lun_blocks = 0;
volatile uint32_t native_ufs_lba0_crc32 = 0;
const char *volatile native_ufs_readonly_failure = nullptr;
}

static bool nabuUfsProperty(IOService *provider, const char *key, void *out, unsigned bytes)
{
  OSData *data = OSDynamicCast(OSData, provider->getProperty(key));
  if (!data || data->getLength() != bytes || !data->getBytesNoCopy()) return false;
  memcpy(out, data->getBytesNoCopy(), bytes);
  return true;
}

static bool nabuUfsFailure(const char *reason)
{
  native_ufs_readonly_failure = reason;
  IOLog("NABU UFS READONLY stage=%u failed: %s\n", native_ufs_readonly_stage, reason);
  // Cached fields only: failure reporting must not probe a wedged bus again.
  IOLog("UFS CACHED GCC gdsc=%08x axi=%08x ahb=%08x\n",
        native_ufs_readonly_gdsc, native_ufs_readonly_axi, native_ufs_readonly_ahb);
  IOLog("UFS CACHED phase=%s cap=%08x ver=%08x dma=%llx\n", gRootDiagnostic.stage,
        gRootDiagnostic.cap, gRootDiagnostic.version, static_cast<unsigned long long>(gRootDiagnostic.dma));
  IOLog("UFS CACHED result=%08x ocs=%x polls=%u dbSeen=%x isSeen=%x\n",
        gRootDiagnostic.result, gRootDiagnostic.ocs, gRootDiagnostic.polls,
        gRootDiagnostic.dbSeen, gRootDiagnostic.isSeen);
  IOLog("UFS CACHED SMMU id1=%08x id2=%08x slot=%u\n",
        gRootDiagnostic.smmuId1, gRootDiagnostic.smmuId2, gRootDiagnostic.smmuSlot);
  IOLog("UFS CACHED ROUTE smr=%08x s2cr=%08x cbar=%08x sctlr=%08x cba2r=%08x\n",
        gRootDiagnostic.smr, gRootDiagnostic.s2cr, gRootDiagnostic.cbar,
        gRootDiagnostic.sctlr, gRootDiagnostic.cba2r);
  return false;
}

bool NativeUfs::start(IOService *provider)
{
  // The historical root personality is not a resource-bearing UFS provider.
  if (!OSDynamicCast(IOPlatformDevice, provider)) return false;
  __atomic_fetch_add(&native_ufs_readonly_starts, 1, __ATOMIC_RELAXED);
  unsigned enabled = 0;
  PE_parse_boot_argn("native-ufs-readonly", &enabled, sizeof(enabled));
  native_ufs_readonly_requested = enabled;
  if (enabled != 1) return false;
  native_ufs_readonly_stage = 1;
  NabuUfsResources r = {};
  if (!nabuUfsProperty(provider, "nabu,ufs-hc", r.hc, sizeof(r.hc)) ||
      !nabuUfsProperty(provider, "nabu,ufs-gcc", r.gcc, sizeof(r.gcc)) ||
      !nabuUfsProperty(provider, "nabu,ufs-smmu", r.smmu, sizeof(r.smmu)) ||
      !nabuUfsProperty(provider, "nabu,ufs-stream", &r.stream, sizeof(r.stream)) ||
      !nabuUfsProperty(provider, "nabu,ufs-block-bytes", &r.blockBytes, sizeof(r.blockBytes)) ||
      !nabuUfsResourcesMatch(r)) return nabuUfsFailure("provider resource contract");
  native_ufs_readonly_stage = 2;
  IOLog("NABU UFS READONLY v1 provider accepted; checking GCC before HC\n");
  OSSharedPtr<IOMemoryMap> clockMap;
  uintptr_t gcc = mapPhys(r.gcc[0], r.gcc[1], clockMap);
  if (!gcc) return nabuUfsFailure("GCC map");
  native_ufs_readonly_stage = 3;
  const auto &b = nabu_ufs::kBoard;
  uint32_t gdsc = read32(gcc, b.gdscr - 0x77000);
  native_ufs_readonly_gdsc = gdsc;
  uint32_t axi = read32(gcc, b.axiEnable - 0x77000);
  native_ufs_readonly_axi = axi;
  uint32_t ahb = read32(gcc, b.ahbEnable - 0x77000);
  native_ufs_readonly_ahb = ahb;
  if (!nabuUfsClocksReady(gdsc, axi, ahb)) return nabuUfsFailure("UFS power/bus clocks unavailable");
  native_ufs_readonly_stage = 4;
  return startReadOnly(provider);
}

bool NativeUfs::startReadOnly(IOService *provider)
{
  const char *why = "transport";
  if (!hostBringUp(&why)) return nabuUfsFailure(why);
  auto failAfterBringup = [](const char *reason) {
    gHost.ready = false;
    gHost.poisoned = true;
    return nabuUfsFailure(reason);
  };
  native_ufs_lun_blocks = gHost.blocks;
  native_ufs_readonly_stage = 5;
  if (hostRead4k(0, 0, 1, gScratch) != kIOReturnSuccess)
    return failAfterBringup("LUN 0 first block read");
  native_ufs_lba0_crc32 = rootCrc32(gScratch, 4096);
  native_ufs_readonly_stage = 6;
  if (!IOService::start(provider)) return failAfterBringup("IOService start");
  NativeUfsBlock *device = OSTypeAlloc(NativeUfsBlock);
  bool attached = false;
  if (device && device->init(static_cast<OSDictionary *>(nullptr)) &&
      device->configurePhysicalLun(gHost.blocks * 4096ULL)) {
    attached = device->attach(this);
    if (attached && device->start(this)) {
      // Keep the service reference and host DMA for this kernel lifetime.
      // Published clients can retain I/O; there is no unproven hot-unplug path.
      native_ufs_blocks_published = native_ufs_blocks_published + 1;
      native_ufs_readonly_stage = 7;
      IOLog("NABU UFS READONLY published LUN0 blocks=%llu blockBytes=4096 lba0_crc=%08x\n",
            static_cast<unsigned long long>(gHost.blocks), native_ufs_lba0_crc32);
      return true;
    }
  }
  if (attached) device->detach(this);
  if (device) device->release();
  IOService::stop(provider);
  return failAfterBringup("raw LUN service publication");
}
