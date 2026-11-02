// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Opt-in liveness heartbeat for the native text console.
//
// The 2026-10-26 UFS Data boot reached the original launchd services and then
// stopped producing console lines at the UFS window-publication message.  A
// photograph of a static screen cannot distinguish "the system is running but
// silent" from "the kernel stopped scheduling", so this thread prints one
// compact counter line on a fixed interval.  It only reads kernel counters and
// writes the console; there is no MMIO, allocation or state change.
//
// Gate: boot-arg nabu-heartbeat=1.  Interval: nabu-heartbeat-interval seconds
// (default 15, clamped to 5..300).  `nabu-heartbeat-counter=1` selects a
// counter/yield wait for diagnostics when timeout wakeups are not trusted.
// Runs for at most one hour.
//
// Linked only into NABU_CAPTURE_LOG builds; the call site is injected by
// nabu_capture_source.py next to the other opt-in console hooks.

#include <IOKit/IOLib.h>
#include <pexpert/pexpert.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include "../ufs/NabuLogCore.h"
#include "../ufs/NabuLogWatch.h"

#ifndef NABU_HEARTBEAT_RAM_ACCOUNTING
#define NABU_HEARTBEAT_RAM_ACCOUNTING 0
#endif

extern "C" {
extern volatile unsigned nabu_log_writer_state;
extern volatile unsigned nabu_log_writer_rounds;
extern volatile unsigned nabu_log_writer_failures;
extern volatile uint64_t armcpu_timer_interrupts;
extern int nprocs;
extern unsigned int vm_page_free_count;
extern unsigned int vm_page_active_count;
extern unsigned int vm_page_wire_count;
extern unsigned int vm_page_inactive_count;
extern unsigned int vm_page_speculative_count;
extern unsigned int vm_page_pageable_internal_count;
extern unsigned int vm_page_pageable_external_count;
extern uint32_t vm_page_pages;
#if NABU_HEARTBEAT_RAM_ACCOUNTING
extern volatile uint64_t native_ram_block_bytes;
extern volatile uint64_t native_ram_block_resident_bytes;
extern volatile uint64_t native_ram_block_reads;
extern volatile uint64_t native_ram_block_writes;
extern volatile uint64_t native_ram_block_failures;
#endif
}

namespace {

void memory_snapshot(const char *source, unsigned sample)
{
	// Independent reads; pageable counts overlap queues and must not be summed.
	IOLog("NABU VM source=%s sample=%u free=%u active=%u inactive=%u speculative=%u wired=%u internal=%u external=%u\n",
	    source, sample, vm_page_free_count, vm_page_active_count,
	    vm_page_inactive_count, vm_page_speculative_count, vm_page_wire_count,
	    vm_page_pageable_internal_count, vm_page_pageable_external_count);
#if NABU_HEARTBEAT_RAM_ACCOUNTING
	IOLog("NABU RAM source=%s sample=%u bytes=%llu resident=%llu reads=%llu writes=%llu failures=%llu\n",
	    source, sample, (unsigned long long)native_ram_block_bytes,
	    (unsigned long long)native_ram_block_resident_bytes,
	    (unsigned long long)native_ram_block_reads, (unsigned long long)native_ram_block_writes,
	    (unsigned long long)native_ram_block_failures);
#endif
}

constexpr unsigned kDefaultInterval = 15;
constexpr unsigned kMinInterval = 5;
constexpr unsigned kMaxInterval = 300;
constexpr unsigned kMaxTicks = 240;   // 240 * interval; one hour at 15 s
unsigned timer_ticks;
unsigned data_stage;
int data_status = -1;

bool counter_wait()
{
	static int cached = -1;
	int value = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
	if (value >= 0) return value == 1;
	int enabled = 0;
	PE_parse_boot_argn("nabu-heartbeat-counter", &enabled, sizeof(enabled));
	__atomic_store_n(&cached, enabled == 1 ? 1 : 0, __ATOMIC_RELEASE);
	return enabled == 1;
}

void counter_sleep(unsigned interval)
{
	uint64_t deadline;
	clock_interval_to_deadline(interval * 1000, kMillisecondScale, &deadline);
	while (mach_absolute_time() < deadline) {
		// Zero has no priority-restoration timer in XNU and can starve this loop.
		thread_yield_internal(1);
	}
}

bool watch_enabled()
{
	static int cached = -1;
	int value = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
	if (value >= 0) return value == 1;
	int enabled = 0;
	PE_parse_boot_argn("nabu-heartbeat", &enabled, sizeof(enabled));
	__atomic_store_n(&cached, enabled == 1 ? 1 : 0, __ATOMIC_RELEASE);
	return enabled == 1;
}

void timer_snapshot(unsigned stage)
{
	uint64_t frequency = 0, counter = 0, control = 0, compare = 0, daif = 0;
	unsigned available = 0;
#if defined(__arm64__) || defined(__aarch64__)
	/* EL1 timer registers already used by this platform. No GIC MMIO or
	 * system-register writes; this path must work before a timer wake. */
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r" (frequency));
	__asm__ volatile("mrs %0, cntvct_el0" : "=r" (counter));
	__asm__ volatile("mrs %0, cntv_ctl_el0" : "=r" (control));
	__asm__ volatile("mrs %0, cntv_cval_el0" : "=r" (compare));
	__asm__ volatile("mrs %0, daif" : "=r" (daif));
	available = 1;
#endif
	IOLog("NABU TIMER stage=%u available=%u irq=%llu timer-ticks=%u freq=%llu count=%llu ctl=%llx cval=%llu daif=%llx\n",
	    stage, available, (unsigned long long)armcpu_timer_interrupts,
	    __atomic_load_n(&timer_ticks, __ATOMIC_RELAXED),
	    (unsigned long long)frequency, (unsigned long long)counter,
	    (unsigned long long)control, (unsigned long long)compare,
	    (unsigned long long)daif);
}

void
nabu_heartbeat_thread(void *, wait_result_t)
{
	unsigned interval = kDefaultInterval;

	PE_parse_boot_argn("nabu-heartbeat-interval", &interval, sizeof(interval));
	if (interval < kMinInterval) {
		interval = kMinInterval;
	} else if (interval > kMaxInterval) {
		interval = kMaxInterval;
	}

	const bool counter = counter_wait();
	IOLog("NABU HB started; wait=%s timer wake not yet verified; log-state=%u commits=%u failures=%u\n",
	    counter ? "counter-yield" : "iosleep",
	    nabu_log_writer_state, nabu_log_writer_rounds, nabu_log_writer_failures);
	for (unsigned tick = 1; tick <= kMaxTicks; ++tick) {
		if (counter) counter_sleep(interval);
		else IOSleep(interval * 1000);
		__atomic_store_n(&timer_ticks, tick, __ATOMIC_RELAXED);
		IOLog("NABU HB t=%u irq=%llu procs=%d free=%u active=%u pages=%u\n",
		    tick * interval,
		    (unsigned long long)armcpu_timer_interrupts,
		    nprocs, vm_page_free_count, vm_page_active_count, vm_page_pages);
		memory_snapshot("heartbeat", tick);
		struct nb_log_snapshot capture;
		const int available = nabu_capture_snapshot(&capture);
		IOLog("NABU LOG state=%u commits=%u failures=%u capture=%d bytes=%llu lost=%llu\n",
		    nabu_log_writer_state, nabu_log_writer_rounds, nabu_log_writer_failures,
		    available, available ? (unsigned long long)capture.end : 0,
		    available ? (unsigned long long)capture.lost : 0);
	}
}

} // namespace

extern "C" void
nabu_data_mount_progress(unsigned stage, int status)
{
	if (!watch_enabled()) return;
	__atomic_store_n(&data_status, status, __ATOMIC_RELAXED);
	__atomic_store_n(&data_stage, stage, __ATOMIC_RELEASE);
	IOLog("NABU DATA trace stage=%u status=%d\n", stage, status);
	timer_snapshot(stage);
}

extern "C" void
nabu_boot_watch_poll(void)
{
	if (!watch_enabled()) return;
	/* The existing writer supplies execution; this adds no polling thread or
	 * sleep. Its counter deadline is independent of the IOSleep heartbeat. */
	static bool started;
	static uint64_t next;
	static unsigned samples;
	if (!started) {
		started = true;
		clock_interval_to_deadline(5000, kMillisecondScale, &next);
		timer_snapshot(0);
		return;
	}
	if (samples >= kMaxTicks || mach_absolute_time() < next) return;
	clock_interval_to_deadline(5000, kMillisecondScale, &next);
	++samples;
	unsigned stage = __atomic_load_n(&data_stage, __ATOMIC_ACQUIRE);
	IOLog("NABU WATCH sample=%u irq=%llu timer-ticks=%u data-stage=%u data-status=%d writer=%u commits=%u failures=%u\n",
	    samples, (unsigned long long)armcpu_timer_interrupts,
	    __atomic_load_n(&timer_ticks, __ATOMIC_RELAXED), stage,
	    __atomic_load_n(&data_status, __ATOMIC_RELAXED),
	    nabu_log_writer_state, nabu_log_writer_rounds, nabu_log_writer_failures);
	memory_snapshot("writer", samples);
}

extern "C" void
nabu_heartbeat_start(void)
{
	int enabled = 0;

	PE_parse_boot_argn("nabu-heartbeat", &enabled, sizeof(enabled));
	if (!enabled) {
		return;
	}

	thread_t thread = nullptr;
	if (kernel_thread_start(nabu_heartbeat_thread, nullptr, &thread) == KERN_SUCCESS) {
		thread_deallocate(thread);
	}
}
