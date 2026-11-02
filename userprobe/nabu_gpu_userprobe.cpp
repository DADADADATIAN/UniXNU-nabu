// SPDX-License-Identifier: MIT
// Owned-BO transport proof only: not a Metal plugin, compositor or launchd.
#include "NativeAdrenoABI.h"
#include "AdrenoPM4.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#ifndef NABU_USERPROBE_ABI_SHA256
#define NABU_USERPROBE_ABI_SHA256 "unbound-host-test"
#endif

namespace nabu_userprobe {
constexpr uint64_t kPage = 4096;
constexpr uint64_t kWaitNs = 2000000000;
constexpr uint32_t kChip = 0x06040001;
constexpr uint32_t kExpected = 0x6402cafe;
constexpr uint32_t kGuardBefore = 0x6402a001, kGuardAfter = 0x6402a002;
constexpr size_t kResultWord = 64;
constexpr uint32_t kMalformed = 0xf6400001, kWrongDevice = 0xf6400002;
constexpr uint32_t kWrongData = 0xf6400003, kPacketFailure = 0xf6400004;
static_assert(NativeAdrenoAbiVersion == 1, "Requalify the probe for an ABI change");
static_assert(sizeof(NativeAdrenoAbiSubmit) == 416, "Probe submit ABI");
static_assert(sizeof(NativeAdrenoAbiBoCpuMapV2) == 24, "Probe CPU-map ABI");

struct Transport {
    void *cookie;
    uint32_t (*call)(void *, uint32_t, const void *, size_t, void *, size_t *);
    void (*trace)(void *, const char *) = nullptr;
};
struct Outcome {
    const char *stage = "not_started", *cleanup_stage = "none";
    uint32_t status = 0, cleanup_status = 0;
    uint32_t before = 0, observed = 0, guard_before = 0, guard_after = 0;
    uint64_t fence = 0;
    bool submitted = false, completed = false, verified = false, cleanup_deferred = false;
};
struct Buffer {
    uint64_t handle = 0, iova = 0, map_id = 0;
    volatile uint32_t *cpu = nullptr;
};

// Existing AGX diagnostic open types only: no new GPU selector or admission.
uint16_t stage_marker(const char *stage) {
    static const char *const names[] = {"entry", "open", "query", "device_info", "queue_create",
        "input_alloc", "input_cpu_map", "input_gpu_map", "output_alloc", "output_cpu_map", "output_gpu_map",
        "status_before", "submit", "wait_fence", "status_after", "report", "output_cpu_unmap", "output_free",
        "input_cpu_unmap", "input_free", "queue_close", "complete"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (!std::strcmp(stage, names[i])) return uint16_t(0x6401 + i);
    return 0x64ff;
}

bool marker_line(void *cookie, bool (*mark)(void *, uint16_t), const char *line) {
    if (!mark || !line) return false;
    size_t bytes = 0;
    while (bytes < 64 && line[bytes]) {
        const unsigned char ch = static_cast<unsigned char>(line[bytes++]);
        if (ch < 32 || ch >= 127) return false;
    }
    if (!bytes || bytes >= 64 || !mark(cookie, 0x7fff)) return false;
    for (size_t i = 0; i < bytes; ++i)
        if (!mark(cookie, uint16_t(0x7000 | static_cast<unsigned char>(line[i])))) return false;
    return true;
}

int final_line(const Outcome &result, uint32_t closed, char line[64]) {
    const bool pass = result.verified && result.completed && !result.status &&
        !result.cleanup_status && !closed && !result.cleanup_deferred;
    const int bytes = std::snprintf(line, 64, "NF p=%u s=%x c=%x x=%x f=%llu d=%u t=%x", pass ? 1u : 0u,
        result.status, result.cleanup_status, closed,
        static_cast<unsigned long long>(result.fence <= UINT32_MAX ? result.fence : 0),
        unsigned(result.cleanup_deferred), unsigned(stage_marker(result.stage)));
    return bytes > 0 && bytes < 64 ? bytes : 0;
}

static void visibility_barrier() {
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("dsb sy" ::: "memory");
#else
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
}

static uint32_t rpc(const Transport &transport, const char *stage, uint32_t method,
                    const void *input, size_t input_bytes, void *output, size_t output_bytes) {
    if (transport.trace) transport.trace(transport.cookie, stage);
    size_t actual = output_bytes;
    const uint32_t status = transport.call(transport.cookie, method, input, input_bytes,
                                           output, &actual);
    return status ? status : actual == output_bytes ? 0 : kMalformed;
}

// A response supplies the per-connection window; no command-line GPU address is accepted.
static bool addresses(const NativeAdrenoAbiParams &params, const NativeAdrenoAbiDeviceInfo &info,
                      uint64_t out[2]) {
    if (params.abi_version != NativeAdrenoAbiVersion || params.input_bits < 32 ||
        params.input_bits > 48 || params.output_bits < 32 || params.output_bits > 48 ||
        params.max_bo_bytes < kPage || !(params.flags & NativeAdrenoParamsCpuMapV2) ||
        info.chip_id != kChip || info.gmem_bytes != 0x100000 || info.reserved ||
        !(info.flags & NativeAdrenoDeviceClientIova) ||
        (info.flags & NativeAdrenoDeviceCachedCoherent) || !info.va_start ||
        (info.va_start & (kPage - 1)) || info.va_size < 2 * kPage ||
        info.va_start > UINT64_MAX - info.va_size ||
        info.va_start + info.va_size > (UINT64_C(1) << params.input_bits)) return false;
    out[0] = info.va_start;
    out[1] = info.va_start + kPage;
    return true;
}

static bool packet(uint64_t output_iova, uint32_t words[4]) {
    if (!output_iova || (output_iova & (kPage - 1)) || output_iova > UINT64_MAX - kPage)
        return false;
    const uint64_t target = output_iova + kResultWord * sizeof(uint32_t);
    // Same bounded CP_MEM_WRITE opcode as the qualified A640 scratch proof.
    if (AdrenoPM4Type7(0x3d, 3, &words[0]) != AdrenoPM4Success) return false;
    words[1] = uint32_t(target); words[2] = uint32_t(target >> 32); words[3] = kExpected;
    AdrenoPM4Packet plan{};
    size_t count = 0;
    return AdrenoPM4Plan(words, 4, &plan, 1, &count) == AdrenoPM4Success &&
        count == 1 && plan.type == 7 && plan.identifier == 0x3d && plan.payload_words == 3;
}

static Outcome run(const Transport &transport) {
    Outcome result;
    if (!transport.call) { result.stage = "transport"; result.status = kMalformed; return result; }
    Buffer buffers[2];
    uint64_t queue = 0;
    auto call = [&](const char *stage, uint32_t method, const void *in, size_t in_bytes,
                    void *out, size_t out_bytes) {
        result.stage = stage;
        result.status = rpc(transport, stage, method, in, in_bytes, out, out_bytes);
        return result.status == 0;
    };
    auto invalid = [&](uint32_t status) { result.status = status; return false; };
    const bool passed = [&]() {
        NativeAdrenoAbiParams params{};
        if (!call("query", NativeAdrenoMethodQuery, nullptr, 0, &params, sizeof(params))) return false;
        NativeAdrenoAbiDeviceInfo info{};
        if (!call("device_info", NativeAdrenoMethodGetDeviceInfo, nullptr, 0, &info, sizeof(info))) return false;
        uint64_t iovas[2]{};
        if (!addresses(params, info, iovas)) return invalid(kWrongDevice);
        NativeAdrenoAbiQueue create_request{};
        NativeAdrenoAbiQueueReply created{};
        if (!call("queue_create", NativeAdrenoMethodCreateQueue, &create_request, sizeof(create_request),
                  &created, sizeof(created))) return false;
        queue = created.queue;
        if (!queue || queue >= NativeAdrenoAbiMaxQueues) { queue = 0; return invalid(kMalformed); }
        for (unsigned i = 0; i < 2; ++i) {
            Buffer &buffer = buffers[i];
            NativeAdrenoAbiBoAlloc request{kPage, 12, 0};
            NativeAdrenoAbiBoAllocReply allocated{};
            if (!call(i ? "output_alloc" : "input_alloc", NativeAdrenoMethodBoAlloc,
                      &request, sizeof(request), &allocated, sizeof(allocated))) return false;
            buffer.handle = allocated.handle;
            if (!buffer.handle || (i && buffer.handle == buffers[0].handle)) {
                buffer.handle = 0; return invalid(kMalformed);
            }
            NativeAdrenoAbiBoCpuMapV2 cpu_request{buffer.handle, 0, NativeAdrenoCpuMapVersion, 0};
            NativeAdrenoAbiBoCpuMapV2Reply cpu_reply{};
            if (!call(i ? "output_cpu_map" : "input_cpu_map", NativeAdrenoMethodBoCpuMapV2,
                      &cpu_request, sizeof(cpu_request), &cpu_reply, sizeof(cpu_reply))) return false;
            buffer.map_id = cpu_reply.map_id;
            if (!buffer.map_id || !cpu_reply.address || cpu_reply.bytes != kPage ||
                (cpu_reply.address & (kPage - 1)) || cpu_reply.address > UINTPTR_MAX - kPage)
                return invalid(kMalformed);
            buffer.cpu = reinterpret_cast<volatile uint32_t *>(uintptr_t(cpu_reply.address));
            NativeAdrenoAbiBoMap gpu_request{buffer.handle, iovas[i], i ? 3u : 1u, 0, 2, 0};
            NativeAdrenoAbiBoMapReply gpu_reply{};
            if (!call(i ? "output_gpu_map" : "input_gpu_map", NativeAdrenoMethodBoMap,
                      &gpu_request, sizeof(gpu_request), &gpu_reply, sizeof(gpu_reply))) return false;
            if (gpu_reply.iova != iovas[i]) return invalid(kMalformed);
            buffer.iova = gpu_reply.iova;
        }
        result.stage = "initial_zero";
        volatile uint32_t *output = buffers[1].cpu;
        result.before = output[kResultWord];
        if (result.before || output[kResultWord - 1] || output[kResultWord + 1]) return invalid(kWrongData);
        output[kResultWord - 1] = kGuardBefore;
        output[kResultWord + 1] = kGuardAfter;
        uint32_t words[4]{};
        if (!packet(buffers[1].iova, words)) return invalid(kPacketFailure);
        for (unsigned i = 0; i < 4; ++i) buffers[0].cpu[i] = words[i];
        visibility_barrier();
        if (output[kResultWord] != 0) return invalid(kWrongData);
        NativeAdrenoAbiStatus before{};
        if (!call("status_before", NativeAdrenoMethodGetStatus, nullptr, 0, &before, sizeof(before))) return false;
        NativeAdrenoAbiSubmit submission{};
        submission.buffer_count = 1; submission.queue = queue;
        submission.buffers[0] = {buffers[0].handle, buffers[0].iova, sizeof(words)};
        NativeAdrenoAbiSubmitReply submitted{};
        // An error or malformed reply may follow a DMA-visible doorbell. Leave ownership to the kernel.
        result.submitted = true;
        if (!call("submit", NativeAdrenoMethodSubmit, &submission, sizeof(submission),
                  &submitted, sizeof(submitted))) return false;
        result.fence = submitted.fence;
        if (!result.fence || result.fence > UINT32_MAX) return invalid(kMalformed);
        NativeAdrenoAbiWaitFence wait{result.fence, kWaitNs};
        if (!call("wait_fence", NativeAdrenoMethodWaitFence, &wait, sizeof(wait), nullptr, 0)) return false;
        result.completed = true;
        visibility_barrier();
        result.observed = output[kResultWord];
        result.guard_before = output[kResultWord - 1]; result.guard_after = output[kResultWord + 1];
        result.stage = "readback";
        if (result.observed != kExpected || result.guard_before != kGuardBefore || result.guard_after != kGuardAfter)
            return invalid(kWrongData);
        NativeAdrenoAbiStatus after{};
        if (!call("status_after", NativeAdrenoMethodGetStatus, nullptr, 0, &after, sizeof(after))) return false;
        if (before.faults != after.faults || before.suspends != after.suspends) return invalid(kWrongDevice);
        NativeAdrenoAbiMetadata metadata{};
        metadata.handle = buffers[1].handle;
        const int length = std::snprintf(metadata.text, sizeof(metadata.text),
            "nabu-owned proof=%08x initial=0 guards=ok fence=%llu", result.observed,
            static_cast<unsigned long long>(result.fence));
        if (length < 0 || size_t(length) >= sizeof(metadata.text)) return invalid(kMalformed);
        metadata.bytes = uint32_t(length);
        if (!call("report", NativeAdrenoMethodSetMetadata, &metadata, sizeof(metadata), nullptr, 0)) return false;
        result.verified = true;
        return true;
    }();
    auto cleanup = [&](const char *stage, uint32_t method, const void *in, size_t in_bytes) {
        const uint32_t status = rpc(transport, stage, method, in, in_bytes, nullptr, 0);
        if (status && !result.cleanup_status) { result.cleanup_status = status; result.cleanup_stage = stage; }
        return status == 0;
    };
    if (!result.submitted || result.completed) {
        for (unsigned i = 2; i-- > 0;) {
            Buffer &buffer = buffers[i];
            if (buffer.map_id) {
                NativeAdrenoAbiBoCpuUnmapV2 unmap{buffer.handle, buffer.map_id};
                if (!cleanup(i ? "output_cpu_unmap" : "input_cpu_unmap", NativeAdrenoMethodBoCpuUnmapV2,
                             &unmap, sizeof(unmap))) continue;
                buffer.map_id = 0;
            }
            if (buffer.handle) {
                NativeAdrenoAbiBoFree free{buffer.handle};
                cleanup(i ? "output_free" : "input_free", NativeAdrenoMethodBoFree, &free, sizeof(free));
            }
        }
        if (queue) {
            NativeAdrenoAbiQueue close{queue};
            cleanup("queue_close", NativeAdrenoMethodCloseQueue, &close, sizeof(close));
        }
    } else {
        result.cleanup_deferred = true;
    }
    if (passed && !result.cleanup_status) result.stage = "complete";
    return result;
}
} // namespace nabu_userprobe

#ifndef NABU_GPU_USERPROBE_TEST
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <unistd.h>

namespace {
struct IOKit {
    void *library = nullptr;
    CFMutableDictionaryRef (*matching)(const char *) = nullptr;
    kern_return_t (*services)(mach_port_t, CFDictionaryRef, mach_port_t *) = nullptr;
    mach_port_t (*next)(mach_port_t) = nullptr;
    kern_return_t (*release)(mach_port_t) = nullptr;
    kern_return_t (*retain)(mach_port_t) = nullptr;
    CFTypeRef (*property)(mach_port_t, CFStringRef, CFAllocatorRef, uint32_t) = nullptr;
    kern_return_t (*registry_id)(mach_port_t, uint64_t *) = nullptr;
    kern_return_t (*open)(mach_port_t, mach_port_t, uint32_t, mach_port_t *) = nullptr;
    kern_return_t (*close)(mach_port_t) = nullptr;
    kern_return_t (*method)(mach_port_t, uint32_t, const void *, size_t, void *, size_t *) = nullptr;
    mach_port_t connection = MACH_PORT_NULL;
    mach_port_t service = MACH_PORT_NULL;
    bool load() {
        library = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
        if (!library) return false;
#define LOAD(field, name) field = reinterpret_cast<decltype(field)>(dlsym(library, name)); if (!field) return false
        LOAD(matching, "IOServiceMatching"); LOAD(services, "IOServiceGetMatchingServices");
        LOAD(next, "IOIteratorNext"); LOAD(release, "IOObjectRelease");
        LOAD(retain, "IOObjectRetain");
        LOAD(property, "IORegistryEntryCreateCFProperty"); LOAD(registry_id, "IORegistryEntryGetRegistryEntryID");
        LOAD(open, "IOServiceOpen"); LOAD(close, "IOServiceClose"); LOAD(method, "IOConnectCallStructMethod");
#undef LOAD
        return true;
    }
    static uint32_t call(void *cookie, uint32_t method, const void *in, size_t in_bytes, void *out, size_t *out_bytes) {
        auto &io = *static_cast<IOKit *>(cookie);
        return uint32_t(io.method(io.connection, method, in, in_bytes, out, out_bytes));
    }
    static bool marker(void *cookie, uint16_t value) {
        auto &io = *static_cast<IOKit *>(cookie);
        if (!io.service) return false;
        mach_port_t extra = MACH_PORT_NULL;
        const uint32_t status = uint32_t(io.open(io.service, mach_task_self(), 0x41470000u | value, &extra));
        const bool refused = status == 0xe00002c7u && !extra; // kIOReturnUnsupported, no connection
        if (extra) (void)io.close(extra);
        return refused;
    }
    static void trace(void *cookie, const char *stage) {
        (void)marker(cookie, nabu_userprobe::stage_marker(stage));
        std::printf("NABU_USERPROBE stage=%s\n", stage);
    }
};
void nonblocking_output(int fd) {
    const int flags = fcntl(fd, F_GETFL);
    // A diagnostic tty must not hold up a GPU request or its watchdog.
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) (void)close(fd);
}
void watchdog(int) {
    static const char line[] = "NABU_USERPROBE result=watchdog kernel_call_completion_unknown\n";
    (void)write(STDERR_FILENO, line, sizeof(line) - 1);
    _exit(124);
}
} // namespace

#if NABU_USERPROBE_TURNIP
#include "NativeTurnipSmoke.h"
namespace nabu_turnip_stage {
// The library is the owner-signed Turnip build in the same /usr/bin union as this executable.
bool library(char *path, size_t size) {
    uint32_t bytes = uint32_t(size);
    char self[1024];
    if (_NSGetExecutablePath(self, &bytes) != 0) return false;
    char *slash = std::strrchr(self, '/');
    if (!slash) return false;
    *slash = 0;
    const int written = std::snprintf(path, size, "%s/libvulkan_freedreno.dylib", self);
    return written > 0 && size_t(written) < size && access(path, R_OK) == 0;
}
// Every smoke stage leaves the same open-type 0x4147 marker the plugin uses (0x6001.., 0x6f/0x6e on failure);
// the summary line "NT ..." goes to the kernel text row for this process, like the owned-BO "NF" line.
void run(IOKit *io, const char *path) {
    setenv("TU_DARWIN_SERVICE", "IOAcceleratorES", 1);
    setenv("TU_DARWIN_OPEN_TYPE", "0x4147", 1);
    auto mark = [io](uint32_t value) { (void)IOKit::marker(io, uint16_t(value)); };
    auto report = [io](const char *text) { (void)nabu_userprobe::marker_line(io, IOKit::marker, text); };
    const turnip::Result r = turnip::runWatched(mark, report, path);
    char line[64];
    const int bytes = std::snprintf(line, sizeof(line), "NT p=%u s=%d r=%d v=%d c=%d g=%d/%d", r.ok ? 1u : 0u,
        r.stage, r.vkResult, r.verified, r.computeWords, r.renderTriangle, r.renderOther);
    if (bytes > 0 && size_t(bytes) < sizeof(line)) (void)nabu_userprobe::marker_line(io, IOKit::marker, line);
    std::printf("NABU_USERPROBE turnip=%s stage=%d vk=%d fill=%d compute=%d compute_stage=%d triangle=%d other=%d "
                "render_stage=%d error=%s\n", r.ok ? "pass" : "fail", r.stage, r.vkResult, r.verified, r.computeWords,
                r.computeStage, r.renderTriangle, r.renderOther, r.renderStage, turnip::gFirstError);
}
}  // namespace nabu_turnip_stage
#endif

int main(int argc, char **argv) {
    nonblocking_output(STDOUT_FILENO);
    nonblocking_output(STDERR_FILENO);
    // Keep stage text in this bounded buffer until GPU cleanup and the final
    // marker are done, including when stdout is an automatically line-buffered tty.
    static char console_buffer[4096];
    if (std::setvbuf(stdout, console_buffer, _IOFBF, sizeof(console_buffer)) != 0)
        (void)close(STDOUT_FILENO);
    if (argc != 2 || std::strcmp(argv[1], "--run-owned-bo")) {
        std::fprintf(stderr, "Usage: nabu-gpu-userprobe --run-owned-bo\nOwned BO proof only; no Metal rendering or installation.\n");
        return 2;
    }
    // Bounds userspace waiting, not a guarantee that a wedged kernel/MMIO call can be interrupted.
    if (signal(SIGALRM, watchdog) == SIG_ERR) {
        std::fprintf(stderr, "NABU_USERPROBE result=fail stage=watchdog_setup\n"); return 1;
    }
    alarm(15);
    IOKit io;
    if (!io.load()) { std::fprintf(stderr, "NABU_USERPROBE result=fail stage=iokit_load\n"); return 10; }
    CFMutableDictionaryRef match = io.matching("AGXAccelerator");
    mach_port_t iterator = MACH_PORT_NULL;
    const uint32_t matched = match ? uint32_t(io.services(MACH_PORT_NULL, match, &iterator)) : nabu_userprobe::kMalformed;
    if (matched || !iterator) {
        const uint32_t released = iterator ? uint32_t(io.release(iterator)) : 0;
        std::fprintf(stderr, "NABU_USERPROBE result=fail stage=matching status=%08x release=%08x\n", matched, released); return 1;
    }
    mach_port_t service = io.next(iterator), extra = io.next(iterator);
    const uint32_t iterator_release = uint32_t(io.release(iterator));
    if (!service || extra || iterator_release) {
        const uint32_t released = service ? uint32_t(io.release(service)) : 0;
        const uint32_t extra_released = extra ? uint32_t(io.release(extra)) : 0;
        std::fprintf(stderr, "NABU_USERPROBE result=fail stage=unique_service status=%08x release=%08x/%08x\n",
                     iterator_release, released, extra_released); return 1;
    }
    CFTypeRef plugin = io.property(service, CFSTR("MetalPluginName"), kCFAllocatorDefault, 0);
    CFTypeRef klass = io.property(service, CFSTR("MetalPluginClassName"), kCFAllocatorDefault, 0);
    const bool own = plugin && klass && CFEqual(plugin, CFSTR("NativeAdrenoMetal")) && CFEqual(klass, CFSTR("NativeAdrenoMetalDevice"));
    if (plugin) CFRelease(plugin);
    if (klass) CFRelease(klass);
    uint64_t registry = 0;
    const uint32_t identified = uint32_t(io.registry_id(service, &registry));
    if (!own || identified || !registry) {
        const uint32_t released = uint32_t(io.release(service));
        std::fprintf(stderr, "NABU_USERPROBE result=fail stage=service_identity status=%08x release=%08x\n",
                     identified, released); return 1;
    }
    if (io.retain(service) != 0) {
        (void)io.release(service);
        std::fprintf(stderr, "NABU_USERPROBE result=fail stage=service_retain\n"); return 11;
    }
    io.service = service;
    (void)IOKit::marker(&io, nabu_userprobe::stage_marker("entry"));
    (void)IOKit::marker(&io, nabu_userprobe::stage_marker("open"));
    const uint32_t opened = uint32_t(io.open(service, mach_task_self(), 0x4147, &io.connection));
    const uint32_t service_release = uint32_t(io.release(service));
    std::printf("NABU_USERPROBE registry=%llu abi_sha256=%s open=%08x service_release=%08x\n",
                static_cast<unsigned long long>(registry), NABU_USERPROBE_ABI_SHA256, opened, service_release);
    if (opened || !io.connection || service_release) {
        const uint32_t closed = io.connection ? uint32_t(io.close(io.connection)) : 0;
        nabu_userprobe::Outcome failure;
        failure.stage = "open"; failure.status = opened ? opened : nabu_userprobe::kMalformed;
        char line[64];
        if (nabu_userprobe::final_line(failure, closed, line))
            (void)nabu_userprobe::marker_line(&io, IOKit::marker, line);
        (void)io.release(io.service);
        std::fprintf(stderr, "NABU_USERPROBE result=fail stage=open close=%08x\n", closed); return 1;
    }
    const auto outcome = nabu_userprobe::run({&io, IOKit::call, IOKit::trace});
    const uint32_t closed = uint32_t(io.close(io.connection));
    char summary[64];
    if (nabu_userprobe::final_line(outcome, closed, summary))
        (void)nabu_userprobe::marker_line(&io, IOKit::marker, summary);
    alarm(0);
#if NABU_USERPROBE_TURNIP
    // The owned-BO verdict above is final and already reported. Only after it passed, and only
    // when the owner-signed Turnip library sits beside this executable, run the Vulkan known-image
    // test on its own connection: fill buffer, compute shader, then a rendered triangle read back.
    char library[1024];
    if (outcome.verified && !outcome.status && !outcome.cleanup_status && !closed &&
        nabu_turnip_stage::library(library, sizeof(library))) {
        // This process has one kernel text row; the Turnip lines replace the NF line. The ESP writer
        // samples that row every 10 s, so wait past one sample before overwriting the owned-BO verdict.
        sleep(11);
        alarm(150);  // the smoke watchdog reports at 15, 45 and 90 s; this bounds a wedged kernel call
        nabu_turnip_stage::run(&io, library);
        alarm(0);
    }
#endif
    const uint32_t diagnostic_release = uint32_t(io.release(io.service));
    const bool pass = outcome.verified && outcome.completed && !outcome.status && !outcome.cleanup_status && !closed && !diagnostic_release;
    std::printf("NABU_USERPROBE result=%s stage=%s status=%08x cleanup_stage=%s cleanup=%08x close=%08x "
                "initial=%08x observed=%08x guards=%08x/%08x fence=%llu completed=%u deferred=%u render_proof=0\n",
                pass ? "pass" : "fail", outcome.stage, outcome.status, outcome.cleanup_stage, outcome.cleanup_status, closed,
                outcome.before, outcome.observed, outcome.guard_before, outcome.guard_after,
                static_cast<unsigned long long>(outcome.fence), unsigned(outcome.completed), unsigned(outcome.cleanup_deferred));
    if (io.library) dlclose(io.library);
    return pass ? 0 : 1;
}
#endif
