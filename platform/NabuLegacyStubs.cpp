// Scanout is unavailable until the console ownership protocol is implemented.
// Discovery must not acquire the screen or claim a successful pixel transfer.
#include <stdint.h>

extern "C" int boot_progress_prepare_scanout(void) { return 0; }
extern "C" void boot_progress_cancel_scanout(void) {}
extern "C" void boot_progress_stage(const char *) {}
extern "C" int boot_progress_pulse_anchor(uintptr_t, uint64_t, unsigned, unsigned, unsigned) {
    return 0;
}
