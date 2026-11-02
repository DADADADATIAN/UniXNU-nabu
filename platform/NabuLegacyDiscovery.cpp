// SPDX-License-Identifier: BSD-2-Clause-Patent
// Display discovery only: no pixel stores, swap parsing or synthetic completion.
#include "OriginalLegacyFramebufferABI.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <pexpert/pexpert.h>

extern "C" __attribute__((noreturn)) void native_legacy_backend_guard(unsigned, void *, void *);
extern "C" bool native_legacy_gop_mapping_observed(IOService *, IOMemoryMap *, uint32_t, uint32_t);
extern "C" void native_legacy_registration_observed(IOService *);
extern "C" void native_legacy_client_enter(task_t, uint32_t);
extern "C" void native_legacy_client_observed(IOReturn, IOUserClient *);
extern "C" {
volatile uint32_t nabu_legacy_discovery_abi = 1;
volatile uint32_t nabu_legacy_discovery_swap_rejections;
volatile uint32_t nabu_legacy_discovery_main_queries, nabu_legacy_discovery_video_display;
}

class NativeLegacyDisplay : public IOMobileFramebufferLegacy {
    OSDeclareDefaultStructors(NativeLegacyDisplay)
    IOMemoryMap *bootMapping = nullptr;
    bool primary = false;
public:
    void free() override {
        primary = false;
        OSSafeReleaseNULL(bootMapping);
        IOMobileFramebufferLegacy::free();
    }
    void stop(IOService *provider) override {
        primary = false;
        IOMobileFramebufferLegacy::stop(provider);
        OSSafeReleaseNULL(bootMapping);
    }
    bool start(IOService *provider) override {
        return IOMobileFramebufferLegacy::start(provider);
    }
    void registerService(IOOptionBits options = 0) override {
        unsigned enabled = 0;
        PE_parse_boot_argn("offline-legacy-register", &enabled, sizeof(enabled));
        if (enabled != 1) native_legacy_backend_guard(84, this, __builtin_return_address(0));
        IOService::registerService(options);
        native_legacy_registration_observed(this);
    }
    bool isMainDisplay() override { ++nabu_legacy_discovery_main_queries; return primary; }
    void kickSwapQueue() override {}
    bool validateSwap(const OriginalLegacySwapRequest *) override {
        ++nabu_legacy_discovery_swap_rejections;
        return false;
    }
    IOReturn getDotPitch(uint32_t *) override { return kIOReturnUnsupported; }
    IOReturn supportedFrameInfo(uint32_t, uint32_t *, char *, uint32_t *) override {
        return kIOReturnUnsupported;
    }
    IOReturn collectCompletionReports(uint32_t, void *, uint32_t *, uint32_t) override {
        return kIOReturnUnsupported;
    }
    IOReturn newUserClient(task_t task, void *security, UInt32 type, IOUserClient **client) override {
        native_legacy_client_enter(task, type);
        IOReturn status = IOMobileFramebufferLegacy::newUserClient(task, security, type, client);
        native_legacy_client_observed(status, status == kIOReturnSuccess && client ? *client : nullptr);
        return status;
    }
    bool startHardware() override {
        unsigned enabled = 0;
        PE_parse_boot_argn("offline-legacy-gop", &enabled, sizeof(enabled));
        if (enabled != 1) return false;
        PE_Video video = {};
        IOService *provider = getProvider();
        if (!provider || PE_current_console(&video) || !video.v_baseAddr ||
            !video.v_width || !video.v_height || video.v_depth != 32 || video.v_rotate ||
            video.v_width > 16384 || video.v_height > 16384 ||
            video.v_rowBytes < video.v_width * 4 ||
            video.v_rowBytes > UINT64_MAX / video.v_height) return false;
        IOMemoryMap *mapping = provider->mapDeviceMemoryWithIndex(0, kIOMapInhibitCache);
        if (!mapping) return false;
        bool valid = mapping->getVirtualAddress() &&
            mapping->getPhysicalAddress() == video.v_baseAddr &&
            mapping->getLength() == video.v_rowBytes * video.v_height;
        if (valid) {
            // The ABI generator verifies slot 249's two original dimension loads.
            installBootDimensions((uint32_t)video.v_width, (uint32_t)video.v_height);
            uint32_t width = 0, height = 0;
            getDisplayDimensions(&width, &height);
            valid = width == video.v_width && height == video.v_height;
            if (valid) {
                OSSafeReleaseNULL(bootMapping);
                bootMapping = mapping;
                mapping = nullptr;
                primary = video.v_display == 1;
                nabu_legacy_discovery_video_display = (uint32_t)video.v_display;
                valid = native_legacy_gop_mapping_observed(this, bootMapping, width, height);
            }
        }
        OSSafeReleaseNULL(mapping);
        return valid;
    }
#define LEAF(n) __attribute__((noreturn,noinline)) void opaque##n() override { native_legacy_backend_guard(n,this,__builtin_return_address(0)); }
    LEAF(211)
    LEAF(245)
    LEAF(246)
    LEAF(306)
    LEAF(307)
    LEAF(338)
    LEAF(345)
#undef LEAF
};
OSDefineMetaClassAndStructors(NativeLegacyDisplay, IOMobileFramebufferLegacy)
extern "C" IOService *native_legacy_display_allocate(void) { return new NativeLegacyDisplay; }
