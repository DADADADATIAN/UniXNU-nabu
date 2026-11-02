// SPDX-License-Identifier: BSD-2-Clause-Patent
// nabu boot-session AON latch for the original AMFI. This is NOT SM8150 power
// hardware management: readAon/writeAon only latch the boot-time state AMFI
// consumes, and every CPU power operation is explicitly unsupported.
#include "OriginalPMGRABI.h"
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <mach/kmod.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
kern_return_t OSKextLoadKextWithIdentifier(const char *);
void nabu_boot_pmgr_static_init(void) __asm__("__GLOBAL__sub_I_NabuBootPMGR.cpp");
IOService *qemu_original_pmgr_nub_create(IORegistryEntry *, ApplePMGR *);
uint32_t nabu_boot_pmgr_aon_value = 0;
volatile uint32_t nabu_boot_pmgr_aon_reads = 0;
volatile uint32_t nabu_boot_pmgr_aon_writes = 0;
volatile uint64_t nabu_boot_pmgr_provider_id = 0;
volatile uint64_t nabu_boot_pmgr_nub_id = 0;
}

class NabuBootPMGR : public ApplePMGR {
  OSDeclareDefaultStructors(NabuBootPMGR)
public:
  bool start(IOService *provider) override { return IOService::start(provider); }
  void stop(IOService *provider) override { IOService::stop(provider); }
  uint32_t readAon() override {
    nabu_boot_pmgr_aon_reads = nabu_boot_pmgr_aon_reads + 1;
    return __atomic_load_n(&nabu_boot_pmgr_aon_value, __ATOMIC_RELAXED);
  }
  void writeAon(uint64_t value) override {
    __atomic_store_n(&nabu_boot_pmgr_aon_value, uint32_t(value), __ATOMIC_RELAXED);
    nabu_boot_pmgr_aon_writes = nabu_boot_pmgr_aon_writes + 1;
  }
  void enableCPUCore(unsigned, uint64_t) override { unsupportedPower(); }
  void enableCPUCore(unsigned) override { unsupportedPower(); }
  void disableCPUCore(unsigned) override { unsupportedPower(); }
  void enableCPUCluster(unsigned) override { unsupportedPower(); }
  void disableCPUCluster(unsigned) override { unsupportedPower(); }
  void initCPUIdle(ml_processor_info_t *) override { unsupportedPower(); }
  void enterCPUIdle(UInt64 *) override { unsupportedPower(); }
  void exitCPUIdle(UInt64 *) override { unsupportedPower(); }
  void updateCPUIdle(UInt64 *) override { unsupportedPower(); }
private:
  __attribute__((noreturn)) static void unsupportedPower() {
    panic("NabuBootPMGR: CPU power operations are not implemented");
  }
};

OSDefineMetaClassWithInit(NabuBootPMGR, ApplePMGR, )
OSMetaClassConstructorInit(NabuBootPMGR, ApplePMGR, )
OSDefineBasicStructors(NabuBootPMGR, ApplePMGR)
// The original parent exceeds the typed-allocation size limit.
void *NabuBootPMGR::operator new(size_t size) { return OSObject::operator new(size); }
void NabuBootPMGR::operator delete(void *memory, size_t size) {
  OSObject::operator delete(memory, size);
}
static_assert(sizeof(NabuBootPMGR) == 0x4b8a8, "Original ApplePMGR storage");

extern "C" bool nabu_boot_pmgr_publish(IOService *platform, IORegistryEntry *description)
{
  kern_return_t result = OSKextLoadKextWithIdentifier("com.apple.driver.ApplePMGR");
  if (result != KERN_SUCCESS) {
    IOLog("NabuBootPMGR: original ApplePMGR load failed %d\n", result);
    return false;
  }
  // The real parent metaclass must exist before the subclass initializer runs.
  void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
  if (handle == nullptr) { return false; }
  nabu_boot_pmgr_static_init();
  result = OSMetaClass::postModLoad(handle);
  if (result != KERN_SUCCESS) {
    IOLog("NabuBootPMGR: subclass registration failed %d\n", result);
    return false;
  }

  NabuBootPMGR *provider = new NabuBootPMGR;
  if (provider == nullptr) { return false; }
  if (!provider->init(description, gIODTPlane) || !provider->attach(platform)) {
    provider->release();
    return false;
  }
  if (!provider->start(platform)) {
    provider->detach(platform);
    provider->release();
    return false;
  }
  IOService *nub = qemu_original_pmgr_nub_create(description, provider);
  if (nub == nullptr || !nub->attach(provider)) {
    if (nub != nullptr) { nub->release(); }
    provider->stop(platform);
    provider->detach(platform);
    provider->release();
    return false;
  }
  if (!nub->start(provider)) {
    nub->detach(provider);
    nub->release();
    provider->stop(platform);
    provider->detach(platform);
    provider->release();
    return false;
  }
  nabu_boot_pmgr_provider_id = provider->getRegistryEntryID();
  nabu_boot_pmgr_nub_id = nub->getRegistryEntryID();
  provider->registerService();
  nub->registerService();
  IOLog("NabuBootPMGR: original %s on %s; AON boot-session value=%u\n",
        nub->getMetaClass()->getClassName(), provider->getMetaClass()->getClassName(),
        __atomic_load_n(&nabu_boot_pmgr_aon_value, __ATOMIC_RELAXED));
  // Both objects and the latch live for this boot. No CPU provider, clocks,
  // sleep or reset capability is registered by this backend.
  return true;
}