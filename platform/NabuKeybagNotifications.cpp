// SPDX-License-Identifier: BSD-2-Clause-Patent
// Ephemeral notification transport. With nabu-aks-state=1 it also answers the
// AppleKeyStore state queries of the unchanged libaks/MobileKeyBag truthfully for
// this environment (UniXNU AppleKeyStoreState 42ff83e): no keybag, no passcode,
// unlocked since boot. It provides no key, keybag, passcode or data-protection
// operation; every other selector fails as an unreachable AppleKeyStore does.
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOLib.h>
#include <libkern/libkern.h>
#include <libkern/c++/OSSymbol.h>
#include <pexpert/pexpert.h>
#include <mach/kmod.h>

#if !defined(NABU_LEGACY_CPU_PRESENT) || !defined(NABU_KEYBAG_RAM_DATA_VERIFIED)
#error Keybag notifications require an explicit CPU profile with verified RAM-Data build dependencies
#endif

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern volatile uint32_t native_owner_data_stage;
extern volatile int native_owner_data_status;
extern volatile uint64_t native_ram_block_bytes;
volatile uint32_t nabu_keybag_notification_stage;
volatile int nabu_keybag_notification_status = kIOReturnNotReady;
volatile uint32_t nabu_keybag_notification_subscriptions, nabu_keybag_notification_failures;
volatile uint32_t nabu_keybag_notification_refused_opens;
volatile uint64_t nabu_keybag_notification_service;
volatile uint32_t nabu_aks_state_opens, nabu_aks_state_calls;
void nabu_keybag_notifications_static_init(void) __asm__("__GLOBAL__sub_I_NabuKeybagNotifications.cpp");
}

namespace {
bool aksStateEnabled()
{
    unsigned enabled = 0;
    return PE_parse_boot_argn("nabu-aks-state", &enabled, sizeof(enabled)) && enabled == 1;
}

// Selectors and layouts as recorded by UniXNU AppleKeyStoreState for the 17.7 libaks.
constexpr uint32_t kSelLockState = 7, kSelGetSystem = 14, kSelDeviceState = 17, kSelExtendedDeviceState = 35;
constexpr uint64_t kUnlockedSinceBoot = 4;
constexpr uint64_t kStateFlags = 4, kNoPasscodeUnlocked = 0;
constexpr IOReturn kAksError = (IOReturn)0xe00002bc;
constexpr IOReturn kAksUnsupported = (IOReturn)0xe00002c7;

size_t derIntegerContent(uint64_t v, uint8_t out[9])
{
    uint8_t raw[8];
    for (int i = 0; i < 8; ++i) raw[i] = (uint8_t)(v >> (56 - 8 * i));
    size_t start = 0, n = 0;
    while (start < 7 && raw[start] == 0) ++start;
    if (raw[start] & 0x80) out[n++] = 0;
    while (start < 8) out[n++] = raw[start++];
    return n;
}

// DER SET of SEQUENCE{UTF8String key, INTEGER value}; 0 when the buffer is too small.
size_t encodeDeviceState(uint8_t *out, size_t capacity)
{
    struct Entry { const char *key; uint64_t value; };
    const Entry entries[] = {{"ss", kStateFlags}, {"sls", kNoPasscodeUnlocked}, {"sb", 0}, {"sfa", 0}, {"sgs", 0},
                             {"sas", 0}, {"sgpe", 0}, {"srcd", 0}, {"sms", 0}, {"bh", 0}};
    size_t total = 0;
    for (const Entry &e : entries) {
        uint8_t c[9];
        total += 2 + (2 + strlen(e.key)) + (2 + derIntegerContent(e.value, c));
    }
    if (total >= 0x80 || total + 2 > capacity) return 0;
    size_t n = 0;
    out[n++] = 0x31; out[n++] = (uint8_t)total;
    for (const Entry &e : entries) {
        uint8_t c[9];
        size_t kl = strlen(e.key), il = derIntegerContent(e.value, c);
        out[n++] = 0x30; out[n++] = (uint8_t)((2 + kl) + (2 + il));
        out[n++] = 0x0c; out[n++] = (uint8_t)kl;
        for (size_t i = 0; i < kl; ++i) out[n++] = (uint8_t)e.key[i];
        out[n++] = 0x02; out[n++] = (uint8_t)il;
        for (size_t i = 0; i < il; ++i) out[n++] = c[i];
    }
    return n;
}
}  // namespace

class AppleKeyStoreUserClient final : public IOUserClient {
    OSDeclareDefaultStructors(AppleKeyStoreUserClient)
public:
    IOReturn clientClose() override { terminate(); return kIOReturnSuccess; }
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args, IOExternalMethodDispatch *,
                            OSObject *, void *) override {
        IOReturn rc = kAksUnsupported;
        if (!args) rc = kAksError;
        else switch (selector) {
        // Open handshake and bag/assertion/notification bookkeeping that needs no answer without keybags.
        case 0: case 4: case 5: case 9: case 12: case 13: case 26: case 27: case 55: case 101: case 102:
            args->scalarOutputCount = 0;
            rc = kIOReturnSuccess;
            break;
        case kSelGetSystem:
            if (args->scalarOutputCount < 1 || !args->scalarOutput) { rc = kIOReturnBadArgument; break; }
            args->scalarOutput[0] = 0;          // system keybag handle 0: keybagd needs no systembag.kb
            args->scalarOutputCount = 1;
            rc = kIOReturnSuccess;
            break;
        case kSelLockState:
            rc = (args->scalarInputCount == 1 && args->scalarOutputCount == 1 && args->scalarOutput)
                     ? kIOReturnSuccess : kIOReturnBadArgument;
            if (rc == kIOReturnSuccess) args->scalarOutput[0] = kUnlockedSinceBoot;
            break;
        case kSelDeviceState:
        case kSelExtendedDeviceState: {
            if (args->scalarInputCount > 1 || args->scalarOutputCount != 0) { rc = kIOReturnBadArgument; break; }
            uint8_t der[160];
            size_t n = encodeDeviceState(der, sizeof der);
            if (!n) { rc = kIOReturnNoSpace; break; }
            if (args->structureOutputDescriptor) {
                if (n > args->structureOutputDescriptor->getLength()) { rc = kIOReturnNoSpace; break; }
                args->structureOutputDescriptor->writeBytes(0, der, n);
                args->structureOutputDescriptorSize = (uint32_t)n;
                rc = kIOReturnSuccess;
            } else if (args->structureOutput && n <= args->structureOutputSize) {
                memcpy(args->structureOutput, der, n);
                args->structureOutputSize = (uint32_t)n;
                rc = kIOReturnSuccess;
            } else {
                rc = kIOReturnNoSpace;
            }
            break;
        }
        default: break;
        }
        uint32_t calls = ++nabu_aks_state_calls;
        if (calls <= 48) IOLog("NABU AKS sel=%u rc=%#x\n", selector, (unsigned)rc);
        return rc;
    }
};
OSDefineMetaClassAndStructors(AppleKeyStoreUserClient, IOUserClient)

// The matching class is the consumer's event ABI. The distinct service name and
// properties identify an owned RAM-only transport, not Apple security hardware.
class AppleKeyStore final : public IOService {
    OSDeclareDefaultStructors(AppleKeyStore)
public:
    bool start(IOService *provider) override {
        if (!IOService::start(provider)) return false;
        setName("Nabu ephemeral keybag notifications");
        if (!setProperty("NabuEphemeralNotificationTransport", true) ||
            !setProperty("HardwareKeyStore", false) || !setProperty("KeyOperationsAvailable", false) ||
            !setProperty("StateQueriesAvailable", aksStateEnabled())) {
            IOService::stop(provider);
            return false;
        }
        registerService();
        return true;
    }
    OSPtr<IONotifier> registerInterest(const OSSymbol *kind, IOServiceInterestHandler handler,
                                     void *target, void *ref = nullptr) override {
        auto notifier = IOService::registerInterest(kind, handler, target, ref);
        if (notifier) ++nabu_keybag_notification_subscriptions;
        else ++nabu_keybag_notification_failures;
        return notifier;
    }
    IOReturn newUserClient(task_t task, void *security, UInt32 type, OSDictionary *properties,
                           IOUserClient **client) override {
        if (client) *client = nullptr;
        if (!client || !aksStateEnabled()) {
            ++nabu_keybag_notification_refused_opens;
            return kIOReturnNotReady;
        }
        AppleKeyStoreUserClient *user = new AppleKeyStoreUserClient;
        if (!user) return kIOReturnNoMemory;
        if (!user->initWithTask(task, security, type, properties) || !user->attach(this)) {
            user->release();
            return kIOReturnError;
        }
        if (!user->start(this)) {
            user->detach(this);
            user->release();
            return kIOReturnError;
        }
        if (++nabu_aks_state_opens <= 8) IOLog("NABU AKS state client opened type=%u\n", (unsigned)type);
        *client = user;
        return kIOReturnSuccess;
    }
    IOReturn newUserClient(task_t task, void *security, UInt32 type, IOUserClient **client) override {
        return newUserClient(task, security, type, nullptr, client);
    }
};
OSDefineMetaClassAndStructors(AppleKeyStore, IOService)

extern "C" void nabu_keybag_notifications_start(void) {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("nabu-keybag-notifications", &enabled, sizeof(enabled)) ||
        enabled != 1 || nabu_keybag_notification_stage) return;
    nabu_keybag_notification_stage = 1;
    if (native_owner_data_stage != 4 || native_owner_data_status || !native_ram_block_bytes) return;
    const OSSymbol *name = OSSymbol::withCString("AppleKeyStore");
    bool absent = name && !OSMetaClass::getMetaClassWithName(name);
    OSSafeReleaseNULL(name);
    if (!absent) {
        nabu_keybag_notification_status = kIOReturnExclusiveAccess;
        return;
    }
    IOService *provider = IOService::getResourceService();
    if (!provider) return;
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return;
    nabu_keybag_notifications_static_init();
    nabu_keybag_notification_status = OSMetaClass::postModLoad(handle);
    if (nabu_keybag_notification_status) return;
    nabu_keybag_notification_stage = 2;
    IOService *service = new AppleKeyStore;
    bool attached = service && service->init() && service->attach(provider);
    if (!attached || !service->start(provider)) {
        if (attached) service->detach(provider);
        OSSafeReleaseNULL(service);
        nabu_keybag_notification_status = kIOReturnError;
        return;
    }
    nabu_keybag_notification_service = (uintptr_t)service;
    nabu_keybag_notification_status = kIOReturnSuccess;
    nabu_keybag_notification_stage = 3;
}
