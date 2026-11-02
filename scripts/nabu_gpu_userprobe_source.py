"""Opt-in boot transport for the signed ABI1 probe; no Apple job replacement."""

RAM_ANCHOR = 'extern "C" int native_ram_block_gpu_addon(const uint8_t **data,uint64_t *bytes) {\n'
RAM_MARKER = '/* NABU_GPU_USERPROBE_INLINE_V1 */'
DATA_MARKER = '\t/* NABU_GPU_USERPROBE_JOB_V1 */\n'
DATA_ANCHOR = 'native_gpu_addon_prepare(proc_t p, user_addr_t scratch)\n{\n'
PARENTS_BEFORE = '\tfor (size_t i = sizeof("/private/var/ngpu/") - 1; parent[i]; ++i) {\n'
PARENTS_AFTER = ('\t/* NABU_GPU_USERPROBE_PARENTS_V1: create ngpu before its children. */\n'
                 '\tfor (size_t i = sizeof("/private/var/") - 1; parent[i]; ++i) {\n')
CACHE_ENTRY_COUNT = 4
EXEC_ANCHOR = 'static int\nexec_activate_image(struct image_params *imgp)\n{\n'
EXEC_LOCAL = '\tint nabu_probe_target = 0; /* NABU_GPU_USERPROBE_EXEC_V1 */\n'
EXEC_ENTER = '''\tnabu_probe_target = !strcmp(excpath, "/usr/bin/nabu-gpu-userprobe") ||
\t    !strcmp(excpath, "/private/var/ngpu/bin/nabu-gpu-userprobe");
\tif (nabu_probe_target) nabu_gpu_userprobe_exec_note(0, proc_getpid(p), 0);
'''
EXEC_RETURN = '\tif (nabu_probe_target) nabu_gpu_userprobe_exec_note(1, proc_getpid(p), error);\n'
EXEC_HELPER = '''/* NABU_GPU_USERPROBE_PROCESS_V1: observation only; never changes exec/exit. */
static uint32_t nabu_probe_process[6];
static int nabu_gpu_userprobe_process_enabled(void)
{
\tint enabled = 0;
\treturn PE_parse_boot_argn("nabu-gpu-userprobe", &enabled, sizeof(enabled)) && enabled == 1;
}
static void nabu_gpu_userprobe_exec_note(unsigned returned, int pid, int error)
{
\tif (!nabu_gpu_userprobe_process_enabled()) return;
\t__atomic_store_n(&nabu_probe_process[3], (uint32_t)pid, __ATOMIC_RELAXED);
\tif (returned) __atomic_store_n(&nabu_probe_process[2], (uint32_t)error, __ATOMIC_RELAXED);
\t__atomic_fetch_add(&nabu_probe_process[returned ? 1 : 0], 1, __ATOMIC_RELAXED);
}
void nabu_gpu_userprobe_exit_note(int pid, int status)
{
\tif (pid <= 0 || (uint32_t)pid != __atomic_load_n(&nabu_probe_process[3], __ATOMIC_RELAXED) ||
\t    !nabu_gpu_userprobe_process_enabled()) return;
\t__atomic_store_n(&nabu_probe_process[5], (uint32_t)status, __ATOMIC_RELAXED);
\t__atomic_fetch_add(&nabu_probe_process[4], 1, __ATOMIC_RELAXED);
}
void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6])
{
\tfor (unsigned i = 0; i < 6; ++i) out[i] = __atomic_load_n(&nabu_probe_process[i], __ATOMIC_RELAXED);
}

'''
EXEC_TRACE_DECL_ANCHOR = 'struct image_params;    /* Forward */\n'
EXEC_TRACE_DECL = 'static void nabu_gpu_userprobe_exec_stage(int, struct image_params *, const char *, int);\n'
EXEC_TRACE_HELPER = '''/* NABU_GPU_USERPROBE_EXEC_STAGES_V1: only the already selected exec PID. */
static unsigned nabu_probe_exec_trace_count;
extern void nabu_capture_append(const char *, unsigned);
static void nabu_gpu_userprobe_exec_stage(int pid, struct image_params *imgp, const char *stage, int result)
{
\tif (pid <= 0 || (uint32_t)pid != __atomic_load_n(&nabu_probe_process[3], __ATOMIC_RELAXED) ||
\t    !nabu_gpu_userprobe_process_enabled() ||
\t    __atomic_fetch_add(&nabu_probe_exec_trace_count, 1, __ATOMIC_RELAXED) >= 32) return;
\tchar line[224];
\t/* getattr has succeeded before either of these two call sites. */
\tconst struct vnode_attr *va = (!strcmp(stage, "mac_exec") || !strcmp(stage, "authorize")) ? imgp->ip_vattr : NULL;
\tconst int bytes = snprintf(line, sizeof(line),
\t    "NabuGPU: probe_exec_stage=%s pid=%d result=%d mac_return=%d csflags=%x flags=%x mode=%o size=%llu\\n",
\t    stage, pid, result, imgp->ip_mac_return, (unsigned)imgp->ip_csflags, (unsigned)imgp->ip_flags,
\t    va ? (unsigned)va->va_mode : 0, va ? (unsigned long long)va->va_data_size : 0);
\tif (bytes > 0 && (unsigned)bytes < sizeof(line)) nabu_capture_append(line, (unsigned)bytes);
}

'''
# Every replacement preserves the original check, return value and order. These
# are per-probe records in the existing RAM capture, not a global exec tracer.
EXEC_TRACE_PAIRS = (
    ('\terror = namei(ndp);\n\tif (error) {\n\t\tif (error == ERESTART)',
     '\terror = namei(ndp);\n\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "lookup", error);\n'
     '\tif (error) {\n\t\tif (error == ERESTART)'),
    ('\terror = exec_check_permissions(imgp);\n',
     '\terror = exec_check_permissions(imgp);\n'
     '\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "permissions", error);\n'),
    ('\t\terror = (*execsw[i].ex_imgact)(imgp);\n',
     '\t\terror = (*execsw[i].ex_imgact)(imgp);\n'
     '\t\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "image", error);\n'),
    ('\terror = mac_vnode_check_exec(imgp->ip_vfs_context, vp, imgp);\n',
     '\terror = mac_vnode_check_exec(imgp->ip_vfs_context, vp, imgp);\n'
     '\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "mac_exec", error);\n'),
    ('\tif ((error = vnode_authorize(vp, NULL, action, imgp->ip_vfs_context)) != 0) {\n',
     '\terror = vnode_authorize(vp, NULL, action, imgp->ip_vfs_context);\n'
     '\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "authorize", error);\n'
     '\tif (error != 0) {\n'),
    ('\tlret = load_machfile(imgp, mach_header, thread, &map, &load_result);\n',
     '\tlret = load_machfile(imgp, mach_header, thread, &map, &load_result);\n'
     '\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "mach_load", (int)lret);\n'),
    ('\terror = exec_handle_sugid(imgp);\n',
     '\terror = exec_handle_sugid(imgp);\n'
     '\tnabu_gpu_userprobe_exec_stage(proc_getpid(p), imgp, "sugid", error);\n'),
)
EXIT_ANCHOR = ('int\nexit_with_reason(proc_t p, int rv, int *retval, boolean_t thread_can_terminate, boolean_t perf_notify,\n'
                '    int jetsam_flags, struct os_reason *exit_reason)\n{\n')
EXIT_HOOK = '''\t/* NABU_GPU_USERPROBE_EXIT_V1: a successful exit must also leave evidence. */
\textern void nabu_gpu_userprobe_exit_note(int, int);
\tnabu_gpu_userprobe_exit_note(proc_getpid(p), rv);
'''
RAM_HELPER = r'''/* NABU_GPU_USERPROBE_INLINE_V1 */
#include "NabuGpuUserprobeAddon.h"
static OSData *nabu_gpu_userprobe_retained;
static int nabu_gpu_userprobe_inline(const uint8_t **data, uint64_t *bytes)
{
  if (!nabu_gpu_userprobe_retained) {
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (!chosen) return 0;
    OSData *blob = OSDynamicCast(OSData, chosen->getProperty("nabu-gpu-userprobe-addon"));
    OSData *identity = OSDynamicCast(OSData, chosen->getProperty("nabu-gpu-userprobe-sha256"));
    if (blob && identity && identity->getLength() == 32 &&
        nabu_gpu_userprobe_addon_valid(static_cast<const uint8_t *>(blob->getBytesNoCopy()), blob->getLength())) {
      SHA256_CTX context;
      uint8_t digest[32];
      SHA256_Init(&context);
      SHA256_Update(&context, blob->getBytesNoCopy(), blob->getLength());
      SHA256_Final(digest, &context);
      if (!memcmp(digest, identity->getBytesNoCopy(), sizeof(digest))) {
        blob->retain();
        nabu_gpu_userprobe_retained = blob;
      }
    }
    chosen->release();
  }
  if (!nabu_gpu_userprobe_retained) return 0;
  *data = static_cast<const uint8_t *>(nabu_gpu_userprobe_retained->getBytesNoCopy());
  *bytes = nabu_gpu_userprobe_retained->getLength();
  return 1;
}

'''
RAM_GATE = '''  uint32_t nabu_probe = 0;
  if (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1)
    return nabu_gpu_userprobe_inline(data, bytes);
'''
DATA_BRANCH = '''\t/* NABU_GPU_USERPROBE_JOB_V1 */
\tuint32_t nabu_probe = 0;
\tif (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1) {
\t\textern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);
\t\textern void (*nabu_log_probe_process_snapshot)(uint32_t *);
\t\t__atomic_store_n(&nabu_log_probe_process_snapshot, nabu_gpu_userprobe_exec_snapshot, __ATOMIC_RELEASE);
\t\tnative_gpu_addon_install(p, scratch);
\t\t/* Four files, five with the owner-signed Turnip library for the Vulkan known-image test,
\t\t * or eight/nine/ten with the owner-signed NativeAdrenoMetal bundle (nine: publish marker,
\t\t * ten/eleven: publish marker with the pipeline-cache pack and/or the client list). */
\t\tif ((native_gpu_addon_files != 4 && native_gpu_addon_files != 5 && native_gpu_addon_files != 8 &&
\t\t    native_gpu_addon_files != 9 && native_gpu_addon_files != 10 && native_gpu_addon_files != 11) ||
\t\t    native_gpu_addon_failed || native_gpu_addon_error) {
\t\t\tprintf("NabuGPU: userprobe addon refused files=%d failed=%d error=%d render_proof=0\\n",
\t\t\t    native_gpu_addon_files, native_gpu_addon_failed, native_gpu_addon_error);
\t\t\treturn;
\t\t}
\t\tstatic const char source[] = "/private/var/ngpu/daemons";
\t\tstatic const char point[] = "/System/Library/LaunchDaemons";
\t\tnative_gpu_addon_mount(p, scratch, 0x600, source, sizeof(source), point, sizeof(point),
\t\t    "/System/Library/LaunchDaemons/com.apple.backboardd.plist",
\t\t    "/System/Library/LaunchDaemons/org.hackios.nabu-gpu-userprobe.plist",
\t\t    &native_gpu_addon2_stage, &native_gpu_addon2_status);
\t\tprintf("NabuGPU: userprobe addon files=%d written=%d same=%d job_stage=%d job_status=%d render_proof=0\\n",
\t\t    native_gpu_addon_files, native_gpu_addon_written, native_gpu_addon_same,
\t\t    native_gpu_addon2_stage, native_gpu_addon2_status);
\t\tif (native_gpu_addon2_stage != 5 || native_gpu_addon2_status) return;
\t\t/* The platform sandbox lets xpcproxy exec a regular file outside /private/var
\t\t * only, so the cached job names the probe through this /usr/bin union view
\t\t * (UniXNU T733 does the same for its owner executable). */
\t\tstatic const char bin_source[] = "/private/var/ngpu/bin";
\t\tstatic const char bin_point[] = "/usr/bin";
\t\tnative_gpu_addon_mount(p, scratch, 0x800, bin_source, sizeof(bin_source), bin_point, sizeof(bin_point),
\t\t    "/usr/bin/IOMFB_FDR_Loader", "/usr/bin/nabu-gpu-userprobe",
\t\t    &native_gpu_addon3_stage, &native_gpu_addon3_status);
\t\tprintf("NabuGPU: userprobe bin_stage=%d bin_status=%d render_proof=0\\n",
\t\t    native_gpu_addon3_stage, native_gpu_addon3_status);
\t\tif (native_gpu_addon3_stage != 5 || native_gpu_addon3_status) return;
\t\t/* The original launchd accepts system jobs from its verified cache.
\t\t * Keep every original job and let its original loader authenticate this
\t\t * owner-signed cache through the explicitly supplied trust module. */
\t\tstatic const char cache_source[] = "/private/var/ngpu/cache";
\t\tstatic const char cache_point[] = "/System/Library/xpc";
\t\tnative_gpu_addon_mount(p, scratch, 0x400, cache_source, sizeof(cache_source),
\t\t    cache_point, sizeof(cache_point), "/System/Library/xpc/foreground_user_endpoints.plist",
\t\t    "/System/Library/xpc/launchd.plist.sig", &native_gpu_addon_stage, &native_gpu_addon_status);
\t\tprintf("NabuGPU: userprobe cache_stage=%d cache_status=%d owner_signed=1 original_jobs_preserved=1 render_proof=0\\n",
\t\t    native_gpu_addon_stage, native_gpu_addon_status);
\t\tif (native_gpu_addon_stage != 5 || native_gpu_addon_status ||
\t\t    (native_gpu_addon_files < 8 || native_gpu_addon_files > 11)) return;
\t\t/* NABU_GPU_USERPROBE_PLUGIN_V1: the original Metal discovery loads
\t\t * /System/Library/Extensions/<MetalPluginName>.bundle; present the owner bundle there,
\t\t * with the sealed A10 bundle still visible below it. Scratch 0xa00..0xb1a, below mkdir's 0xc00. */
\t\tstatic volatile int nabu_gpu_plugin_stage = 0, nabu_gpu_plugin_status = -1;
\t\tconst int publish = native_gpu_addon_files >= 9;
\t\tvnode_t marker = NULLVP;
\t\tif (!publish && !vnode_lookup("/private/var/ngpu/addons/NativeAdrenoMetal.publish", 0, &marker, vfs_context_current())) {
\t\t\t/* A test-mode addon must not inherit a publish marker from an earlier boot. */
\t\t\tvnode_put(marker);
\t\t\tnabu_gpu_plugin_status = EEXIST;
\t\t} else {
\t\t\tstatic const char plugin_source[] = "/private/var/ngpu/addons";
\t\t\tstatic const char plugin_point[] = "/System/Library/Extensions";
\t\t\tnative_gpu_addon_mount(p, scratch, 0xa00, plugin_source, sizeof(plugin_source), plugin_point,
\t\t\t    sizeof(plugin_point), "/System/Library/Extensions/AGXMetalA10.bundle",
\t\t\t    "/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist",
\t\t\t    &nabu_gpu_plugin_stage, &nabu_gpu_plugin_status);
\t\t}
\t\tprintf("NabuGPU: userprobe plugin_stage=%d plugin_status=%d publish=%d render_proof=0\\n",
\t\t    nabu_gpu_plugin_stage, nabu_gpu_plugin_status, publish);
\t\treturn;
\t}
'''


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('GPU userprobe source drift: ' + old[:90])
    return text.replace(old, new, 1)


def ram_source(text):
    if RAM_MARKER in text:
        if text.count(RAM_HELPER) != 1 or text.count(RAM_GATE) != 1:
            raise ValueError('GPU userprobe RAM source changed after patching')
        return text
    text = once(text, RAM_ANCHOR, RAM_HELPER + RAM_ANCHOR)
    return once(text, '  *data=nullptr;*bytes=0;\n', '  *data=nullptr;*bytes=0;\n' + RAM_GATE)


def data_source(text, restore=False):
    if DATA_MARKER in text:
        if text.count(DATA_BRANCH) != 1:
            raise ValueError('GPU userprobe Data source changed after patching')
        if text.count(PARENTS_AFTER) != 1 or PARENTS_BEFORE in text:
            raise ValueError('GPU userprobe parent creation changed after patching')
        result = text.replace(DATA_BRANCH, '', 1).replace(PARENTS_AFTER, PARENTS_BEFORE, 1) if restore else text
        return exec_source(result, restore=restore)
    if restore:
        return text
    text = once(text, PARENTS_BEFORE, PARENTS_AFTER)
    return exec_source(once(text, DATA_ANCHOR, DATA_ANCHOR + DATA_BRANCH))


def exec_trace_source(text, restore=False):
    marker = '/* NABU_GPU_USERPROBE_EXEC_STAGES_V1:'
    if marker in text and EXEC_TRACE_HELPER not in text:
        raise ValueError('GPU userprobe exec stage helper changed')
    if EXEC_TRACE_HELPER in text:
        if text.count(EXEC_TRACE_DECL_ANCHOR + EXEC_TRACE_DECL) != 1 or any(
                text.count(after) != 1 for _, after in EXEC_TRACE_PAIRS):
            raise ValueError('GPU userprobe exec stage hooks changed')
        if not restore:
            return text
        text = once(text, EXEC_TRACE_DECL, '')
        text = once(text, EXEC_TRACE_HELPER, '')
        for before, after in EXEC_TRACE_PAIRS:
            text = once(text, after, before)
        return text
    if restore:
        return text
    text = once(text, EXEC_TRACE_DECL_ANCHOR, EXEC_TRACE_DECL_ANCHOR + EXEC_TRACE_DECL)
    text = once(text, EXEC_HELPER, EXEC_HELPER + EXEC_TRACE_HELPER)
    for before, after in EXEC_TRACE_PAIRS:
        text = once(text, before, after)
    return text


def exec_source(text, restore=False):
    if restore:
        text = exec_trace_source(text, restore=True)
    enter = '\tDTRACE_PROC1(exec, uintptr_t, excpath);\n'
    returned = '\tkfree_type(struct nameidata, ndp);\n\n\treturn error;\n'
    if 'NABU_GPU_USERPROBE_PROCESS_V1' in text and EXEC_HELPER not in text:
        raise ValueError('GPU userprobe process helper changed')
    if EXEC_HELPER in text:
        for expected in (EXEC_ANCHOR + EXEC_LOCAL, enter + EXEC_ENTER, EXEC_RETURN + returned):
            if text.count(expected) != 1:
                raise ValueError('GPU userprobe process observer changed')
        if not restore:
            return exec_trace_source(text)
        for old, new in ((EXEC_HELPER, ''), (EXEC_LOCAL, ''), (EXEC_ENTER, ''), (EXEC_RETURN, '')):
            text = once(text, old, new)
        return text
    if restore:
        return text
    text = once(text, EXEC_ANCHOR, EXEC_HELPER + EXEC_ANCHOR + EXEC_LOCAL)
    text = once(text, enter, enter + EXEC_ENTER)
    return exec_trace_source(once(text, returned, EXEC_RETURN + returned))


def exit_source(text, restore=False):
    if 'NABU_GPU_USERPROBE_EXIT_V1' in text and EXIT_HOOK not in text:
        raise ValueError('GPU userprobe exit observer changed')
    if EXIT_HOOK in text:
        if text.count(EXIT_ANCHOR + EXIT_HOOK) != 1:
            raise ValueError('GPU userprobe exit observer changed')
        return once(text, EXIT_HOOK, '') if restore else text
    if restore:
        return text
    return once(text, EXIT_ANCHOR, EXIT_ANCHOR + EXIT_HOOK)
