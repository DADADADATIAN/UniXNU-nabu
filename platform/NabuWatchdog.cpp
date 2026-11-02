// SPDX-License-Identifier: BSD-2-Clause-Patent
// nabu publisher for the original 21H16 IOWatchdog service. This is NOT an
// SM8150 hardware watchdog: the three SoC hooks perform no MMIO. The original
// IOWatchdog base parses Apple's wdt boot-arg; publication requires wdt=-1 so
// the base selects its own "watchdog disabled by boot-arg" configuration.
#include "OriginalIOWatchdogABI.h"
#include <IOKit/IOLib.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
kern_return_t OSKextLoadKextWithIdentifier(const char *);
void nabu_watchdog_static_init(void) __asm__("__GLOBAL__sub_I_NabuWatchdog.cpp");
volatile uint32_t nabu_watchdog_soc_enable_calls = 0;
volatile uint32_t nabu_watchdog_soc_disable_calls = 0;
volatile uint32_t nabu_watchdog_soc_pet_calls = 0;
volatile uint64_t nabu_watchdog_registry_id = 0;
}

class NabuWatchdog : public IOWatchdog {
  OSDeclareDefaultStructors(NabuWatchdog)
public:
  bool start(IOService *provider) override {
    // Original base init: locks, boot-args, properties, registerService and
    // IOService::start. With wdt=-1 it never calls the SoC enable hook.
    return original_iowatchdog_init(this, provider, nullptr, 0);
  }
  void socWatchdogEnable() override { nabu_watchdog_soc_enable_calls = nabu_watchdog_soc_enable_calls + 1; }
  void socWatchdogDisable() override { nabu_watchdog_soc_disable_calls = nabu_watchdog_soc_disable_calls + 1; }
  void socWatchdogPet() override { nabu_watchdog_soc_pet_calls = nabu_watchdog_soc_pet_calls + 1; }
};

OSDefineMetaClassAndStructors(NabuWatchdog, IOWatchdog)
static_assert(sizeof(NabuWatchdog) == 0xf8, "Original IOWatchdog storage");

extern "C" bool nabu_watchdog_publish(IOService *platform)
{
  uint64_t wdt = 0;
  if (!PE_parse_boot_argn("wdt", &wdt, sizeof(wdt)) || wdt != UINT64_MAX) {
    IOLog("NabuWatchdog: not published; requires wdt=-1 (no SM8150 watchdog backend)\n");
    return false;
  }
  kern_return_t result = OSKextLoadKextWithIdentifier("com.apple.driver.AppleARMWatchdogTimer");
  if (result != KERN_SUCCESS) {
    IOLog("NabuWatchdog: original AppleARMWatchdogTimer load failed %d\n", result);
    return false;
  }
  // The original IOWatchdog metaclass must exist before the subclass initializer runs.
  void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
  if (handle == nullptr) { return false; }
  nabu_watchdog_static_init();
  result = OSMetaClass::postModLoad(handle);
  if (result != KERN_SUCCESS) {
    IOLog("NabuWatchdog: subclass registration failed %d\n", result);
    return false;
  }
  NabuWatchdog *watchdog = new NabuWatchdog;
  if (watchdog == nullptr) { return false; }
  if (!watchdog->init(nullptr) || !watchdog->attach(platform)) {
    watchdog->release();
    return false;
  }
  watchdog->setProperty("nabu,soc-watchdog-hardware", false);
  if (!watchdog->start(platform)) {
    watchdog->detach(platform);
    watchdog->release();
    IOLog("NabuWatchdog: original IOWatchdog start failed\n");
    return false;
  }
  nabu_watchdog_registry_id = watchdog->getRegistryEntryID();
  IOLog("NabuWatchdog: original IOWatchdog published registry-id=%llu; SoC watchdog hardware absent\n",
        (unsigned long long)nabu_watchdog_registry_id);
  // The published service lives for this boot, like NabuBootPMGR.
  return true;
}
