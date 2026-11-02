"""Keep optional graphics loading out of the nabu root-mount dependency chain.

Transform the pinned patches, not a previously built kernel.  An independent
worker is launched after verified SystemOS/Data setup, before init exec. This
does not repair or qualify IOSurface itself: a stuck worker is still a failure.
"""
import hashlib
import re


LEGACY_PATCH = 'patches/xnu/offline-legacy-start.patch'
LEGACY_PATCH_SHA256 = 'a6ed6012f215e2c13c09f1b89fe986616af0a0674b0f6e4afd2194d4b8de4c0c'

WORKER = '''
/* The Data preparation caller has finished the actual root/cache/Data setup.
 * Never wait for original graphics services on the BSD init thread. */
volatile unsigned nabu_graphics_worker_stage;
volatile int nabu_graphics_thread_status = -1;

static void
nabu_graphics_worker(void *parameter, wait_result_t wait_result)
{
\t(void)parameter;
\t(void)wait_result;
\tnabu_graphics_worker_stage = 2;
\tprintf("NABU GRAPHICS: worker begin after root\\n");
\tnative_mobile_graphics_load_probe();
#if defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY
\tif (native_mobile_graphics_load_status == KERN_SUCCESS) {
\t\textern void native_legacy_display_late_probe(void);
\t\tnabu_graphics_worker_stage = 3;
\t\tnative_legacy_display_late_probe();
\t}
#endif
\tnabu_graphics_worker_stage = 4;
\tprintf("NABU GRAPHICS: worker returned family=%d\\n", native_mobile_graphics_load_status);
\tthread_terminate(current_thread());
}

void
nabu_graphics_start_after_root(void)
{
\tint enabled = 0;
\tif (!PE_parse_boot_argn("offline-mobile-graphics-load", &enabled, sizeof(enabled)) || !enabled) {
\t\treturn;
\t}
\tthread_t worker = THREAD_NULL;
#if defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY
\textern void native_legacy_status_start(void);
\tnative_legacy_status_start();
#endif
\tnabu_graphics_worker_stage = 1;
\tprintf("NABU GRAPHICS: root ready; scheduling worker\\n");
\tkern_return_t result = kernel_thread_start(nabu_graphics_worker, NULL, &worker);
\tnabu_graphics_thread_status = result;
\tif (result == KERN_SUCCESS) {
\t\tthread_deallocate(worker);
\t} else {
\t\tnabu_graphics_worker_stage = 5;
\t\tprintf("NABU GRAPHICS: worker creation failed=%d\\n", result);
\t}
}
'''

AFTER_ROOT_PATCH = '''--- a/bsd/kern/bsd_init.c
+++ b/bsd/kern/bsd_init.c
@@ -1282,7 +1282,9 @@ bsd_autoconf(void)
 \t\t}
 \t}
 
+\t/* nabu starts graphics only after verified SystemOS/Data preparation.
+\t * Keep IOBSD publication and root matching free of display waits. */
 \treturn IOKitBSDInit();
 }
 
 
'''


def _replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Pinned graphics startup patch changed; refuse ambiguous replacement')
    return text.replace(before, after, 1)


def _recount_hunks(text):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)', line)
        if not match:
            continue
        body = []
        for item in lines[index + 1:]:
            if item.startswith(('@@ ', '--- a/', 'diff --git ')):
                break
            body.append(item)
        old = sum(item.startswith((' ', '-')) for item in body)
        new = sum(item.startswith((' ', '+')) for item in body)
        lines[index] = f'@@ -{match[1]},{old} +{match[2]},{new} @@{match[3]}\n'
    return ''.join(lines)


def retime_graphics_patches(component, legacy):
    if hashlib.sha256(legacy).hexdigest() != LEGACY_PATCH_SHA256:
        raise ValueError('Unexpected upstream legacy startup patch')
    text = component.decode('utf-8')
    text = _replace_once(text, '+\tnative_mobile_graphics_load_probe();\n', '')
    load = '+\tnative_mobile_graphics_load_status = OSKextLoadKextWithIdentifier("com.apple.iokit.IOMobileGraphicsFamily");\n'
    text = _replace_once(text, load,
                         '+\tprintf("NABU GRAPHICS: family load begin\\n");\n' + load +
                         '+\tprintf("NABU GRAPHICS: family load returned=%d\\n", native_mobile_graphics_load_status);\n')
    marker = '+#endif\n+\n void\n bsd_init(void)\n'
    worker = ''.join('+' + line + '\n' for line in WORKER.splitlines())
    text = _replace_once(text, marker, worker + marker)
    return _recount_hunks(text).encode('utf-8'), AFTER_ROOT_PATCH.encode('utf-8')
