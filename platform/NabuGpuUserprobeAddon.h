/* SPDX-License-Identifier: MIT */
/* Closed ABI1 probe addon, with an optional owner-signed launchd job cache and,
 * with that cache, an optional owner-signed Turnip library for the Vulkan known-image test
 * or the owner-signed NativeAdrenoMetal plugin bundle for the original Metal discovery. */
#ifndef NABU_GPU_USERPROBE_ADDON_H
#define NABU_GPU_USERPROBE_ADDON_H
#include <stdint.h>
#include <string.h>

/* Without the Turnip library the bound stays 1 MiB; with it, the packed addon (zlib) stays within the
 * 16 MiB DarwinBoot ADT sidecar read and the library itself within 32 MiB. */
#define NABU_GPU_USERPROBE_ADDON_MAX 1048576u
#define NABU_GPU_USERPROBE_TURNIP_ADDON_MAX 12582912u
#define NABU_GPU_USERPROBE_TURNIP_MAX 33554432u
#define NABU_GPU_USERPROBE_EXE_MAX 131072u
#define NABU_GPU_USERPROBE_PLIST_MAX 4096u
#define NABU_GPU_USERPROBE_CACHE_MAX 2097152u
#define NABU_GPU_USERPROBE_SIGNATURE_MAX 65536u
/* The NativeAdrenoMetal plugin form: within the DarwinBoot 16 MiB ADT read together with the ~290 KB base ADT. */
#define NABU_GPU_USERPROBE_PLUGIN_ADDON_MAX 15728640u
#define NABU_GPU_USERPROBE_PLUGIN_INFO_MAX 4096u
#define NABU_GPU_USERPROBE_PLUGIN_EXE_MAX 67108864u
#define NABU_GPU_USERPROBE_PLUGIN_SEAL_MAX 65536u
#define NABU_GPU_USERPROBE_PLUGIN_PUBLISH_MAX 16u
/* An earlier boot's pipeline-cache pack (SHEXP001), imported by the published plugin before its device opens. */
#define NABU_GPU_USERPROBE_PLUGIN_PACK_MAX 8388608u
/* Processes besides backboardd that get their own native Metal device (NativeAdrenoMetalPlugin.mm listedClient). */
#define NABU_GPU_USERPROBE_PLUGIN_CLIENTS_MAX 256u

static inline uint32_t nabu_probe_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t nabu_probe_u64(const uint8_t *p)
{
    return (uint64_t)nabu_probe_u32(p) | ((uint64_t)nabu_probe_u32(p + 4) << 32);
}

static inline int nabu_probe_zero(const uint8_t *p, uint64_t bytes)
{
    for (uint64_t i = 0; i < bytes; ++i) if (p[i]) return 0;
    return 1;
}

/* The closed file kinds. Forms: 2 (probe, job), 4 (+ cache, signature), 5 (+ Turnip),
 * 8/9 (+ the NativeAdrenoMetal bundle, 9 with the publish marker), 10 (9 + the pipeline pack); the published
 * plugin forms may also carry the client list (9/10 become 10/11). */
struct nabu_gpu_userprobe_kind {
    const char *name;
    uint32_t mode;
    uint64_t max;
};
static const struct nabu_gpu_userprobe_kind nabu_gpu_userprobe_kinds[] = {
    {"bin/nabu-gpu-userprobe", 0755, NABU_GPU_USERPROBE_EXE_MAX},
    {"daemons/org.hackios.nabu-gpu-userprobe.plist", 0644, NABU_GPU_USERPROBE_PLIST_MAX},
    {"cache/launchd.plist", 0644, NABU_GPU_USERPROBE_CACHE_MAX},
    {"cache/launchd.plist.sig", 0644, NABU_GPU_USERPROBE_SIGNATURE_MAX},
    {"bin/libvulkan_freedreno.dylib", 0644, NABU_GPU_USERPROBE_TURNIP_MAX},
    {"addons/NativeAdrenoMetal.bundle/Info.plist", 0644, NABU_GPU_USERPROBE_PLUGIN_INFO_MAX},
    {"addons/NativeAdrenoMetal.bundle/NativeAdrenoMetal", 0755, NABU_GPU_USERPROBE_PLUGIN_EXE_MAX},
    {"addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib", 0755, NABU_GPU_USERPROBE_TURNIP_MAX},
    {"addons/NativeAdrenoMetal.bundle/_CodeSignature/CodeResources", 0644, NABU_GPU_USERPROBE_PLUGIN_SEAL_MAX},
    {"addons/NativeAdrenoMetal.publish", 0644, NABU_GPU_USERPROBE_PLUGIN_PUBLISH_MAX},
    {"addons/NativeAdrenoMetal.m2vpack", 0644, NABU_GPU_USERPROBE_PLUGIN_PACK_MAX},
    {"addons/NativeAdrenoMetal.clients", 0644, NABU_GPU_USERPROBE_PLUGIN_CLIENTS_MAX},
};
#define NABU_GPU_USERPROBE_KIND_COUNT (sizeof(nabu_gpu_userprobe_kinds) / sizeof(nabu_gpu_userprobe_kinds[0]))
/* The exact kind set of each form, bit i for nabu_gpu_userprobe_kinds[i]. */
#define NABU_GPU_USERPROBE_SET_PROBE 0x003u
#define NABU_GPU_USERPROBE_SET_CACHE 0x00fu
#define NABU_GPU_USERPROBE_SET_TURNIP 0x01fu
#define NABU_GPU_USERPROBE_SET_PLUGIN 0x1efu
#define NABU_GPU_USERPROBE_SET_PUBLISH 0x3efu
#define NABU_GPU_USERPROBE_SET_PACK 0x7efu
#define NABU_GPU_USERPROBE_SET_CLIENTS_BIT 0x800u

static inline int nabu_gpu_userprobe_addon_valid(const uint8_t *data, uint64_t bytes)
{
    if (!data || bytes < 24 || memcmp(data, "NGPUADD2", 8) ||
        nabu_probe_u32(data + 12) || nabu_probe_u64(data + 16) != bytes) return 0;
    const unsigned count = nabu_probe_u32(data + 8);
    unsigned expected;
    uint64_t limit;
    switch (count) {
    case 2: expected = NABU_GPU_USERPROBE_SET_PROBE; limit = NABU_GPU_USERPROBE_ADDON_MAX; break;
    case 4: expected = NABU_GPU_USERPROBE_SET_CACHE; limit = NABU_GPU_USERPROBE_ADDON_MAX; break;
    case 5: expected = NABU_GPU_USERPROBE_SET_TURNIP; limit = NABU_GPU_USERPROBE_TURNIP_ADDON_MAX; break;
    case 8: expected = NABU_GPU_USERPROBE_SET_PLUGIN; limit = NABU_GPU_USERPROBE_PLUGIN_ADDON_MAX; break;
    case 9: expected = NABU_GPU_USERPROBE_SET_PUBLISH; limit = NABU_GPU_USERPROBE_PLUGIN_ADDON_MAX; break;
    case 10: expected = NABU_GPU_USERPROBE_SET_PACK; limit = NABU_GPU_USERPROBE_PLUGIN_ADDON_MAX; break;
    case 11: expected = NABU_GPU_USERPROBE_SET_PACK | NABU_GPU_USERPROBE_SET_CLIENTS_BIT; limit = NABU_GPU_USERPROBE_PLUGIN_ADDON_MAX; break;
    default: return 0;
    }
    /* Ten files are either the pack form or the published form with the client list: the names decide. */
    const unsigned alternative = count == 10 ? (NABU_GPU_USERPROBE_SET_PUBLISH | NABU_GPU_USERPROBE_SET_CLIENTS_BIT) : expected;
    if (bytes > limit) return 0;
    uint64_t at = 24;
    unsigned seen = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (at > bytes || bytes - at < 24) return 0;
        const uint32_t name_bytes = nabu_probe_u32(data + at);
        const uint32_t mode = nabu_probe_u32(data + at + 4);
        const uint64_t size = nabu_probe_u64(data + at + 8);
        const uint64_t packed = nabu_probe_u64(data + at + 16);
        at += 24;
        if (name_bytes < 2 || name_bytes > 160 || !packed || packed > limit) return 0;
        const uint64_t name_padded = ((uint64_t)name_bytes + 7) & ~UINT64_C(7);
        const uint64_t packed_padded = (packed + 7) & ~UINT64_C(7);
        if (bytes - at < name_padded || bytes - at - name_padded < packed_padded) return 0;
        unsigned kind = 0;
        for (unsigned k = 0; k < NABU_GPU_USERPROBE_KIND_COUNT; ++k) {
            const struct nabu_gpu_userprobe_kind *entry = &nabu_gpu_userprobe_kinds[k];
            if (((expected | alternative) & (1u << k)) && name_bytes == strlen(entry->name) + 1 &&
                !memcmp(data + at, entry->name, name_bytes) && mode == entry->mode && size && size <= entry->max) {
                kind = 1u << k;
                break;
            }
        }
        if (!kind || (seen & kind) ||
            !nabu_probe_zero(data + at + name_bytes, name_padded - name_bytes) ||
            !nabu_probe_zero(data + at + name_padded + packed, packed_padded - packed)) return 0;
        seen |= kind;
        at += name_padded + packed_padded;
    }
    return (seen == expected || seen == alternative) && at == bytes;
}
#endif
