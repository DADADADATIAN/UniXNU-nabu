// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Opt-in CDC-ACM channel for the SM8150 USB0 DWC3 controller, fed from the
// NABULOG2 RAM capture ring (NabuLogCore.h).
//
// This is a bounded rewrite of the archived NativeDwc3 material, not a
// transplant:
//   * No RPMh/SPMI/PMIC/TLMM/rail or GCC write is performed. The
//     bootloader already leaves USB30_PRIM powered and the DWC3 core readable
//     (hardware v2: gdscr=f8222000, no halted branch, GSNPSID=33313130).  This
//     file checks those read-only gates and then writes only the DWC3 core and
//     the dwc-usb3-msm QSCRATCH wrapper, plus the PHY's two VBUS override bits.
//   * A worker starts after bsd_autoconf() (IOKitBSDInit). DMA memory is static BSS,
//     translated with ml_vtophys(), mapped cache-inhibited with ml_io_map(),
//     and the cacheable alias is cleaned once before the core owns the pages.
//   * SMMU descriptors use the authoritative SMMUv2 layout in NabuUsbSmmu.h.
//     Any DMA-enabling step needs the explicit nabu-usb-cdc-log-smmu=1
//     argument; without it the driver stops before the event ring or any TRB
//     can reach the controller.
//   * EP0 multi-packet IN data sets HWO on every TRB in the chain.  The
//     archive set HWO only on the head, which is the shape of its "core retried
//     the next TRB forever" comment.  The 67-byte configuration descriptor
//     becomes 64 + 3-byte TRBs with HWO on both, CHN on the first and
//     IOC|LST on the last, and no trailing ZLP because 67 % 64 != 0.
//   * All command polls, event drains and pump rounds are bounded.
//
// Boot arguments (all absent by default):
//   nabu-usb-cdc-log=1        enable any access to this file (else zero MMIO)
//   nabu-usb-cdc-log-init=1   allow core/QSCRATCH initialization writes
//   nabu-usb-cdc-log-smmu=1   allow SMMU planning and DMA enablement
//   nabu-usb-cdc-log-rounds=N pump rounds (default 20000, clamped to 60000)
//
// Build gate: compiled and linked only when NABU_CAPTURE_LOG=1; the call site
// is injected by nabu_capture_source.py after bsd_autoconf().

#include "NabuUsbCaptureRegs.h"
#include "NabuUsbSmmu.h"
#include "../ufs/NabuLogCore.h"

#include <IOKit/IOLib.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>
#include <vm/pmap.h>
#include <kern/thread.h>
#include <stdarg.h>

extern "C" vm_offset_t ml_io_map(vm_offset_t pa, vm_size_t size);
extern "C" vm_offset_t ml_vtophys(vm_offset_t va);
/* osfmk/arm/caches_asm.s: clean+invalidate by virtual address to PoC. */
extern "C" void FlushPoC_DcacheRegion(vm_offset_t va, unsigned length);

#if defined(NABU_USB_HOST_TEST)
/* Host regression seam: identical call sites, scripted hardware. */
extern "C" uint32_t nabu_usb_test_mmio_read(volatile uint32_t *base, uint32_t offset);
extern "C" void nabu_usb_test_mmio_write(volatile uint32_t *base, uint32_t offset,
    uint32_t value);
#endif

namespace nabu_usb_capture {
namespace {

/* ------------------------------------------------------------------------- */
/* MMIO and bounded waits                                                    */
/* ------------------------------------------------------------------------- */

static inline void
mmio_barrier(void)
{
#if defined(__aarch64__)
	__asm__ volatile ("dsb sy" ::: "memory");
#else
	__asm__ volatile ("" ::: "memory");
#endif
}

static inline void
cpu_relax(void)
{
#if defined(__aarch64__)
	__asm__ volatile ("yield" ::: "memory");
#else
	__asm__ volatile ("" ::: "memory");
#endif
}

static inline uint32_t
mrd(volatile uint32_t *base, uint32_t offset)
{
#if defined(NABU_USB_HOST_TEST)
	return nabu_usb_test_mmio_read(base, offset);
#else
	const uint32_t value = base[offset / 4u];
#if defined(__aarch64__)
	__asm__ volatile ("dmb oshld" ::: "memory");
#endif
	return value;
#endif
}

static inline void
mwr(volatile uint32_t *base, uint32_t offset, uint32_t value)
{
#if defined(NABU_USB_HOST_TEST)
	nabu_usb_test_mmio_write(base, offset, value);
#else
	base[offset / 4u] = value;
#if defined(__aarch64__)
	__asm__ volatile ("dsb sy" ::: "memory");
#endif
#endif
}

static bool
wait_mask(volatile uint32_t *base, uint32_t offset, uint32_t mask,
    uint32_t value, unsigned spins)
{
	for (unsigned i = 0; i < spins; ++i) {
		if ((mrd(base, offset) & mask) == value) {
			return true;
		}
		cpu_relax();
	}
	return false;
}

static void
spin(unsigned count)
{
	for (unsigned i = 0; i < count; ++i) {
		cpu_relax();
	}
}

/* ------------------------------------------------------------------------- */
/* Static DMA pages                                                          */
/* ------------------------------------------------------------------------- */
// Page-aligned BSS.  Zeroed through the cacheable alias before this runs,
// cache-cleaned once, then accessed only through the cache-inhibited alias.
alignas(4096) uint8_t g_event_block[4096];
alignas(4096) uint8_t g_ep0_block[4096];
alignas(4096) uint8_t g_bulk_block[4096];

volatile uint32_t *g_gcc;
volatile uint32_t *g_regs;
volatile uint32_t *g_smmu;
volatile uint32_t *g_phy;
volatile uint32_t *g_evt;
volatile uint32_t *g_ep0;
volatile uint32_t *g_bulk;
uint64_t g_event_pa;
uint64_t g_ep0_pa;
uint64_t g_bulk_pa;
bool g_started;
bool g_faulted;
uint32_t g_resources[32];
uint32_t g_evt_cursor;

/* EP0 block: 16 TRB slots at 0x000, 1 KiB staging at 0x100. */
constexpr uint32_t kEp0Stage = 0x100u;
constexpr uint32_t kEp0StageBytes = 1024u;
constexpr uint32_t kEp0MaxTrbs = 16u;

/* Bulk block: one TRB at 0x000, 1 KiB payload staging at 0x100. */
constexpr uint32_t kBulkStage = 0x100u;
constexpr uint32_t kBulkChunk = 512u;

/* ------------------------------------------------------------------------- */
/* Logging                                                                   */
/* ------------------------------------------------------------------------- */
static void
log_cdc(const char *fmt, ...)
{
	char line[240];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	IOLog("%s", line);
}

static void
puts_cdc(const char *text)
{
	IOLog("%s", text);
}

/* ------------------------------------------------------------------------- */
/* EP0 state                                                                 */
/* ------------------------------------------------------------------------- */
enum {
	kEp0Setup = 0,
	kEp0Data = 1,
	kEp0WaitStatus = 2,
	kEp0Status = 3,
};

int g_ep0_state;
bool g_ep0_three;
bool g_ep0_in;
bool g_ep0_zlp;
unsigned g_ep0_status_dep;
unsigned g_ep0_trbs;
unsigned g_ep0_data_dep;
unsigned g_ep0_armed;
bool g_data_eps_programmed;
unsigned g_configured;
unsigned g_setups;
unsigned g_events;
bool g_bulk_enabled;
bool g_bulk_busy;
uint32_t g_bulk_rsc;
unsigned g_bulk_len;
uint64_t g_log_cursor;
unsigned long long g_log_sent;
unsigned long long g_log_dropped;

/* ------------------------------------------------------------------------- */
/* Controller commands                                                       */
/* ------------------------------------------------------------------------- */
static int
ep_cmd(unsigned dep, uint32_t cmd, uint32_t p0, uint32_t p1, uint32_t p2,
    uint32_t *out_reg)
{
	const uint32_t cfg = mrd(g_regs, kDwc3Gusb2phycfg0);
	const uint32_t drop = cfg & (kGusb2phycfgSusphy | kGusb2phycfgEnblslpm);
	if (drop) {
		mwr(g_regs, kDwc3Gusb2phycfg0, cfg & ~drop);
	}
	mwr(g_regs, depcmdpar0(dep), p0);
	mwr(g_regs, depcmdpar1(dep), p1);
	mwr(g_regs, depcmdpar2(dep), p2);
	mwr(g_regs, depcmd(dep), cmd | kDepcmdCmdact);

	uint32_t reg = 0;
	int status = -1;
	for (unsigned i = 0; i < 20000; ++i) {
		reg = mrd(g_regs, depcmd(dep));
		if ((reg & kDepcmdCmdact) == 0) {
			status = static_cast<int>((reg & kDepcmdStatusMask) >>
			    kDepcmdStatusShift);
			break;
		}
		cpu_relax();
	}
	if (out_reg != nullptr) {
		*out_reg = reg;
	}
	if (drop) {
		mwr(g_regs, kDwc3Gusb2phycfg0, cfg);
	}
	if (status != 0) {
		g_faulted = true;
		log_cdc("NABU USB CDCLOG command-failed dep=%u cmd=%u status=%d\n",
		    dep, cmd & 0xfu, status);
	} else if ((cmd & 0xfu) == kDepcmdStartTransfer) {
		g_resources[dep] = (reg >> kDepcmdParamShift) & 0x7fu;
	}
	return status;
}

static uint32_t
ep_enable(unsigned dep, uint32_t type, uint32_t maxpacket, uint32_t action)
{
	const uint32_t p0 = action | (type << kDepcfgEpTypeShift) |
	    (maxpacket << kDepcfgMaxPacketShift) |
	    ((dep & 1u) ? ((dep >> 1) << kDepcfgFifoShift) : 0u);
	uint32_t p1 = kDepcfgXferCompleteEn;
	if (dep <= 1) {
		p1 |= kDepcfgXferNotReadyEn;
	}
	if (type != kEpTypeControl) {
		p1 |= kDepcfgXferInProgressEn;
	}
	p1 |= dep << kDepcfgEpNumberShift;
	uint32_t reg = 0;
	(void)ep_cmd(dep, kDepcmdSetEpConfig, p0, p1, 0, &reg);
	return (reg >> kDepcmdParamShift) & 0x7fu;
}

static void
ep_end_transfer(unsigned dep, uint32_t rsc)
{
	const uint32_t resource = g_resources[dep];
	(void)rsc;
	if (resource == 0) {
		return;
	}
	(void)ep_cmd(dep, kDepcmdEndTransfer | (1u << 11) |
	    ((resource & 0x7fu) << kDepcmdParamShift), 0, 0, 0, nullptr);
	g_resources[dep] = 0;
}

static void
dalepena_set(unsigned dep, bool on)
{
	uint32_t v = mrd(g_regs, kDwc3Dalepena);
	if (on) {
		v |= dalepena_ep(dep);
	} else {
		v &= ~dalepena_ep(dep);
	}
	mwr(g_regs, kDwc3Dalepena, v);
}

/* ------------------------------------------------------------------------- */
/* Read-only gates and core initialization                                   */
/* ------------------------------------------------------------------------- */
static bool
gcc_gate_readonly(void)
{
	g_gcc = reinterpret_cast<volatile uint32_t *>(
	    ml_io_map(static_cast<vm_offset_t>(kGccBase),
	    static_cast<vm_size_t>(kGccSize)));
	if (g_gcc == nullptr) {
		puts_cdc("NABU USB CDCLOG gcc=map-fail\n");
		return false;
	}
	const uint32_t gdscr = mrd(g_gcc, kGccGdscr);
	if ((gdscr & kGccGdscrPwrOn) == 0) {
		puts_cdc("NABU USB CDCLOG verdict=gdsc-pwr-off\n");
		return false;
	}
	static const uint32_t gates[] = {
		kGccMasterClk, kGccSleepClk, kGccMockUtmiClk,
		kGccCfgNocClk, kGccAggreClk,
	};
	for (unsigned i = 0; i < sizeof(gates) / sizeof(gates[0]); ++i) {
		if (mrd(g_gcc, gates[i]) & kGccBranchClkOff) {
			puts_cdc("NABU USB CDCLOG verdict=clocks-halted\n");
			return false;
		}
	}
	return true;
}

/* QSCRATCH clock gating and UTMI clock routing.  VBUS-valid is applied
 * separately immediately before RUN_STOP, matching the vendor ordering. */
static void
qscratch_clocks(void)
{
	const uint32_t cg = mrd(g_regs, kQscratch + kQCgctl);
	mwr(g_regs, kQscratch + kQCgctl, cg | 0x18u);
	const uint32_t gen = mrd(g_regs, kQscratch + kQGeneralCfg);
	mwr(g_regs, kQscratch + kQGeneralCfg,
	    gen | kQPipeUtmiClkSel | kQPipe3PhystatusSw);
}

static void
qscratch_vbus(void)
{
	const uint32_t hs = mrd(g_regs, kQscratch + kQHsPhyCtrl);
	mwr(g_regs, kQscratch + kQHsPhyCtrl, hs | kQUtmiOtgVbusValid);
	log_cdc("NABU USB CDCLOG qscratch hs=%08x\n",
	    mrd(g_regs, kQscratch + kQHsPhyCtrl));
}

static bool
core_init(void)
{
	const uint32_t gctl = mrd(g_regs, kDwc3Gctl);
	mwr(g_regs, kDwc3Gctl, gctl | kGctlCoresoftreset);
	if (!wait_mask(g_regs, kDwc3Gctl, kGctlCoresoftreset,
	    kGctlCoresoftreset, 10000)) {
		puts_cdc("NABU USB CDCLOG core-reset-set-timeout\n");
		return false;
	}
	mwr(g_regs, kDwc3Gctl, gctl & ~kGctlCoresoftreset);
	if (!wait_mask(g_regs, kDwc3Gctl, kGctlCoresoftreset, 0, 10000)) {
		puts_cdc("NABU USB CDCLOG core-reset-stuck\n");
		return false;
	}

	/* The bootloader can leave PRTCAPDIR=host; keep the other GCTL bits but
	 * force device mode. */
	mwr(g_regs, kDwc3Gctl, (gctl & ~kGctlPrtcapdirMask) |
	    (kGctlPrtcapDevice << kGctlPrtcapdirShift) | kGctlDsblclkgtng);
	spin(200000);

	const uint32_t dctl = mrd(g_regs, kDwc3Dctl) & ~kDctlRunStop;
	mwr(g_regs, kDwc3Dctl, dctl | kDctlCsftrst);
	if (!wait_mask(g_regs, kDwc3Dctl, kDctlCsftrst, 0, 2000000)) {
		puts_cdc("NABU USB CDCLOG device-reset-stuck\n");
		return false;
	}

	uint32_t g2 = mrd(g_regs, kDwc3Gusb2phycfg0);
	g2 &= ~kGusb2phycfgEnblslpm;
	mwr(g_regs, kDwc3Gusb2phycfg0, g2 | kGusb2phycfgPhysftrst);
	spin(20000);
	mwr(g_regs, kDwc3Gusb2phycfg0, g2 & ~kGusb2phycfgPhysftrst);
	spin(20000);

	mwr(g_regs, kDwc3Gusb3pipectl0,
	    mrd(g_regs, kDwc3Gusb3pipectl0) | kGusb3pipectlSusphy);
	uint32_t dcfg = mrd(g_regs, kDwc3Dcfg);
	dcfg &= ~(kDcfgSpeedMask | kDcfgDevaddrMask);
	dcfg |= kDcfgHighSpeed;
	mwr(g_regs, kDwc3Dcfg, dcfg);
	return true;
}

static void
event_program(void)
{
	mwr(g_regs, kDwc3Gevntadrlo, static_cast<uint32_t>(g_event_pa));
	mwr(g_regs, kDwc3Gevntadrhi, static_cast<uint32_t>(g_event_pa >> 32));
	mwr(g_regs, kDwc3Gevntsiz, 4096u & kGevntsizSizeMask);
	const uint32_t stale = mrd(g_regs, kDwc3Gevntcount) & kGevntcountMask;
	mwr(g_regs, kDwc3Gevntcount, stale);
	g_evt_cursor = 0;
	mwr(g_regs, kDwc3Gevten, kGevtenEnable);
	mwr(g_regs, kDwc3Devten, kDevtenBasic);
}

static void
ep0_program(void)
{
	(void)ep_cmd(0, kDepcmdDepStartCfg, 0, 0, 0, nullptr);
	static const unsigned endpoints[] = {0u, 1u, 2u, 3u, 5u};
	for (unsigned dep : endpoints) {
		if (ep_cmd(dep, kDepcmdSetTransferResource,
		    1u, 0, 0, nullptr) != 0) {
			return;
		}
	}
	(void)ep_enable(0, kEpTypeControl, 64, kDepcfgActionInit);
	(void)ep_enable(1, kEpTypeControl, 64, kDepcfgActionInit);
	dalepena_set(0, true);
	dalepena_set(1, true);
	g_ep0_state = kEp0Setup;
	g_ep0_three = false;
	g_ep0_in = false;
	g_ep0_zlp = false;
	g_ep0_trbs = 0;
	g_ep0_armed = 0;
	g_setups = 0;
	g_events = 0;
	g_data_eps_programmed = false;
	puts_cdc("NABU USB CDCLOG ep0=programmed\n");
}

/* ------------------------------------------------------------------------- */
/* EP0 TRBs                                                                  */
/* ------------------------------------------------------------------------- */
static inline volatile uint32_t *
ep0_trb(unsigned slot)
{
	return g_ep0 + slot * 4u;
}

static void
ep0_trb_prepare(unsigned slot, uint64_t buf, uint32_t size, uint32_t type,
    bool chain)
{
	volatile uint32_t *t = ep0_trb(slot);
	t[0] = static_cast<uint32_t>(buf);
	t[1] = static_cast<uint32_t>(buf >> 32);
	t[2] = size;
	t[3] = type | kTrbCtrlIspImi |
	    (chain ? kTrbCtrlChn : (kTrbCtrlIoc | kTrbCtrlLst));
}

/* HWO must be set on every TRB the core may fetch; a chained TRB with HWO
 * clear is what the archive's single-head HWO produced.  All fields are
 * complete before any HWO is published. */
static void
ep0_trb_commit(unsigned slots)
{
	mmio_barrier();
	for (unsigned i = slots; i > 0; --i) {
		ep0_trb(i - 1)[3] |= kTrbCtrlHwo;
	}
	mmio_barrier();
}

static int
ep0_start(unsigned dep)
{
	mmio_barrier();
	return ep_cmd(dep, kDepcmdStartTransfer,
	    static_cast<uint32_t>(g_ep0_pa >> 32),
	    static_cast<uint32_t>(g_ep0_pa), 0, nullptr);
}

static void
ep0_arm_setup(void)
{
	g_ep0_state = kEp0Setup;
	g_ep0_three = false;
	g_ep0_in = false;
	g_ep0_zlp = false;
	g_ep0_trbs = 1;
	g_ep0_data_dep = 0;
	g_ep0_armed = 0;
	ep0_trb_prepare(0, g_ep0_pa, 8, kTrbctlControlSetup, false);
	ep0_trb_commit(1);
	(void)ep0_start(0);
}

static uint8_t *
ep0_stage(void)
{
	return reinterpret_cast<uint8_t *>(const_cast<uint32_t *>(g_ep0)) + kEp0Stage;
}

static void
stage_put(unsigned offset, const void *src, unsigned length)
{
	volatile uint8_t *dst = ep0_stage() + offset;
	const uint8_t *s = static_cast<const uint8_t *>(src);
	for (unsigned i = 0; i < length; ++i) {
		dst[i] = s[i];
	}
	mmio_barrier();
}

static void
stage_put_byte(unsigned offset, uint8_t value)
{
	ep0_stage()[offset] = value;
}

static unsigned
string_desc(unsigned index, uint8_t *out)
{
	static const char *const strings[] = {
		"", "nabu", "nabu console", "0000000001",
	};
	if (index == 0) {
		out[0] = 4;
		out[1] = 3;
		out[2] = 0x09;
		out[3] = 0x04;
		return 4;
	}
	if (index >= sizeof(strings) / sizeof(strings[0])) {
		return 0;
	}
	const char *s = strings[index];
	unsigned n = 0;
	while (s[n] != '\0' && n < 63) {
		++n;
	}
	out[0] = static_cast<uint8_t>(2 + 2 * n);
	out[1] = 3;
	for (unsigned i = 0; i < n; ++i) {
		out[2 + 2 * i] = static_cast<uint8_t>(s[i]);
		out[3 + 2 * i] = 0;
	}
	return 2 + 2 * n;
}

/* IN: one TRB per 64-byte packet, HWO on every entry, CHN except on the last.
 * OUT: a non-aligned length uses the Linux two-TRB align form (full length
 * chained to one maxpacket-remainder TRB). */
static void
ep0_data(unsigned dep, unsigned buf_off, uint32_t len)
{
	g_ep0_state = kEp0Data;
	g_ep0_data_dep = dep;
	g_ep0_trbs = 0;
	g_ep0_armed = len;
	if (dep != 0) {
		if (len == 0) {
			ep0_trb_prepare(0, g_ep0_pa + buf_off, 0,
			    kTrbctlControlData, false);
			g_ep0_trbs = 1;
		} else if (len > 64u) {
			const unsigned packets = (len + 63u) / 64u;
			if (packets > kEp0MaxTrbs) {
				puts_cdc("NABU USB CDCLOG ep0-too-long\n");
				return;
			}
			g_ep0_trbs = packets;
			for (unsigned i = 0; i < packets; ++i) {
				const uint32_t sent = i * 64u;
				const uint32_t chunk = (len - sent) > 64u ? 64u : (len - sent);
				ep0_trb_prepare(i, g_ep0_pa + buf_off + sent, chunk,
				    kTrbctlControlData, i + 1u != packets);
			}
		} else {
			ep0_trb_prepare(0, g_ep0_pa + buf_off, len,
			    kTrbctlControlData, false);
			g_ep0_trbs = 1;
		}
	} else if (len != 0 && (len % 64u) != 0) {
		const uint32_t remainder = 64u - (len % 64u);
		ep0_trb_prepare(0, g_ep0_pa + buf_off, len,
		    kTrbctlControlData, true);
		ep0_trb_prepare(1, g_ep0_pa + kEp0Stage + kEp0StageBytes - 64u,
		    remainder, kTrbctlControlData, false);
		g_ep0_trbs = 2;
	} else {
		ep0_trb_prepare(0, g_ep0_pa + buf_off, len,
		    kTrbctlControlData, false);
		g_ep0_trbs = 1;
	}
	ep0_trb_commit(g_ep0_trbs);
	const int status = ep0_start(dep);
	if (status != 0) {
		log_cdc("NABU USB CDCLOG ep0-data-cmd=%d dep=%u len=%u\n",
		    status, dep, len);
	}
}

static void
ep0_status(unsigned dep)
{
	g_ep0_state = kEp0Status;
	g_ep0_trbs = 1;
	ep0_trb_prepare(0, g_ep0_pa, 0,
	    g_ep0_three ? kTrbctlControlStatus3 : kTrbctlControlStatus2, false);
	ep0_trb_commit(1);
	const int status = ep0_start(dep);
	if (status != 0) {
		log_cdc("NABU USB CDCLOG status-cmd=%d dep=%u\n", status, dep);
	}
}

static void
ep0_restart(void)
{
	ep_end_transfer(0, 0);
	ep_end_transfer(1, 0);
	/* Keep EP0 stalled until the host issues a new SETUP. */
	(void)ep_cmd(0, kDepcmdSetStall, 0, 0, 0, nullptr);
	ep0_arm_setup();
}

static void
enable_data_endpoints(void)
{
	/* Linux re-applies endpoint configuration with MODIFY after the first
	 * INIT; INIT on an already-enabled endpoint is not the documented path. */
	const uint32_t action = g_data_eps_programmed ?
	    kDepcfgActionModify : kDepcfgActionInit;
	(void)ep_enable(physical_ep(1, false), kEpTypeBulk, 512, action);
	g_bulk_rsc = ep_enable(physical_ep(1, true), kEpTypeBulk, 512, action);
	(void)ep_enable(physical_ep(2, true), kEpTypeInterrupt, 16, action);
	dalepena_set(physical_ep(1, false), true);
	dalepena_set(physical_ep(1, true), true);
	dalepena_set(physical_ep(2, true), true);
	g_data_eps_programmed = true;
	g_bulk_enabled = true;
	puts_cdc("NABU USB CDCLOG data-eps=enabled\n");
}

static void
disable_data_endpoints(void)
{
	g_bulk_enabled = false;
	g_bulk_busy = false;
	dalepena_set(physical_ep(1, false), false);
	dalepena_set(physical_ep(1, true), false);
	dalepena_set(physical_ep(2, true), false);
}

/* ------------------------------------------------------------------------- */
/* SETUP handling                                                            */
/* ------------------------------------------------------------------------- */
static void
ep0_setup(void)
{
	const uint32_t w0 = mrd(g_ep0, 0);
	const uint32_t w1 = mrd(g_ep0, 4);
	const uint8_t rt = w0 & 0xffu;
	const uint8_t req = (w0 >> 8) & 0xffu;
	const uint16_t val = (w0 >> 16) & 0xffffu;
	const uint16_t idx = w1 & 0xffffu;
	const uint16_t len = (w1 >> 16) & 0xffffu;

	++g_setups;
	g_ep0_three = len != 0;
	g_ep0_in = g_ep0_three && (rt & 0x80u) != 0;
	g_ep0_zlp = false;
	g_ep0_status_dep = g_ep0_in ? 0u : 1u;
	log_cdc("NABU USB CDCLOG setup rt=%02x req=%02x val=%04x idx=%04x len=%u\n",
	    rt, req, val, idx, len);

	unsigned resp = 0;
	bool stall = false;

	if ((rt & 0x60u) == 0) {
		switch (req) {
		case 6: { /* GET_DESCRIPTOR */
			const unsigned type = val >> 8;
			if (type == 1) {
				stage_put(0, kDeviceDesc, sizeof(kDeviceDesc));
				resp = sizeof(kDeviceDesc);
			} else if (type == 2) {
				stage_put(0, kConfigDesc, sizeof(kConfigDesc));
				resp = sizeof(kConfigDesc);
			} else if (type == 3) {
				uint8_t desc[128];
				resp = string_desc(val & 0xffu, desc);
				if (resp == 0) {
					stall = true;
				} else {
					stage_put(0, desc, resp);
				}
			} else {
				stall = true;
			}
			break;
		}
		case 0: /* GET_STATUS */
			stage_put_byte(0, 0);
			stage_put_byte(1, 0);
			resp = 2;
			break;
		case 5: /* SET_ADDRESS: DCFG before the status stage */
			{
				uint32_t dcfg = mrd(g_regs, kDwc3Dcfg);
				dcfg &= ~kDcfgDevaddrMask;
				dcfg |= static_cast<uint32_t>(val & 0x7fu) <<
				    kDcfgDevaddrShift;
				mwr(g_regs, kDwc3Dcfg, dcfg);
				log_cdc("NABU USB CDCLOG dcfg-set=%08x\n",
				    mrd(g_regs, kDwc3Dcfg));
			}
			break;
		case 8: /* GET_CONFIGURATION */
			stage_put_byte(0, static_cast<uint8_t>(g_configured));
			resp = 1;
			break;
		case 9: /* SET_CONFIGURATION */
			g_configured = val;
			if (val != 0) {
				enable_data_endpoints();
			} else {
				disable_data_endpoints();
			}
			log_cdc("NABU USB CDCLOG configured=%u\n", g_configured);
			break;
		case 10: /* GET_INTERFACE */
			stage_put_byte(0, 0);
			resp = 1;
			break;
		case 1: /* CLEAR_FEATURE */
		case 3: /* SET_FEATURE */
		case 11: /* SET_INTERFACE */
			break;
		default:
			stall = true;
			break;
		}
	} else if (req == 0x21) { /* CDC GET_LINE_CODING: 115200 8N1 */
		static const uint8_t coding[7] = { 0x00, 0xC2, 0x01, 0x00, 0, 0, 8 };
		stage_put(0, coding, sizeof(coding));
		resp = sizeof(coding);
	} else if (req == 0x20 || req == 0x22 || req == 0x23) {
		/* SET_LINE_CODING (OUT data), SET_CONTROL_LINE_STATE, SEND_BREAK. */
	} else {
		stall = true;
	}

	if (stall) {
		puts_cdc("NABU USB CDCLOG stall\n");
		ep0_restart();
		return;
	}
	if (resp > len) {
		resp = len;
	}
	if (resp > kEp0StageBytes) {
		puts_cdc("NABU USB CDCLOG response-too-long\n");
		ep0_restart();
		return;
	}

	if (!g_ep0_three) {
		g_ep0_state = kEp0WaitStatus;
		return;
	}
	if (g_ep0_in) {
		g_ep0_zlp = resp < len && resp != 0 && (resp % 64u) == 0;
		ep0_data(1, kEp0Stage, resp);
	} else {
		if (len > kEp0StageBytes) {
			puts_cdc("NABU USB CDCLOG out-too-long\n");
			ep0_restart();
			return;
		}
		ep0_data(0, kEp0Stage, len);
	}
}

/* ------------------------------------------------------------------------- */
/* Events and capture-ring pump                                              */
/* ------------------------------------------------------------------------- */
static void
bulk_pump(void)
{
	if (!g_bulk_enabled || g_bulk_busy || g_bulk == nullptr) {
		return;
	}
	struct nb_log_snapshot snap;
	if (!nabu_capture_snapshot(&snap)) {
		return;
	}
	if (snap.end <= g_log_cursor) {
		return;
	}
	const uint64_t oldest = snap.end > NB_LOG_CAPACITY ?
	    snap.end - NB_LOG_CAPACITY : 0;
	if (g_log_cursor < oldest) {
		g_log_dropped += oldest - g_log_cursor;
		g_log_cursor = oldest;
	}
	unsigned n = static_cast<unsigned>(snap.end - g_log_cursor);
	if (n > kBulkChunk) {
		n = kBulkChunk;
	}
	uint8_t *stage = reinterpret_cast<uint8_t *>(
	    const_cast<uint32_t *>(g_bulk)) + kBulkStage;
	if (!nabu_capture_copy(g_log_cursor, n, stage)) {
		return;
	}
	/* The staging page is accessed only through the cache-inhibited alias;
	 * the cacheable alias was cleaned once in dma_setup().  A barrier makes
	 * the uncached payload stores visible before the TRB publishes HWO. */
	volatile uint32_t *t = g_bulk;
	t[0] = static_cast<uint32_t>(g_bulk_pa + kBulkStage);
	t[1] = static_cast<uint32_t>((g_bulk_pa + kBulkStage) >> 32);
	t[2] = n;
	mmio_barrier();
	t[3] = kTrbctlNormal | kTrbCtrlIspImi | kTrbCtrlIoc | kTrbCtrlLst |
	    kTrbCtrlHwo;
	mmio_barrier();
	const int status = ep_cmd(3, kDepcmdStartTransfer,
	    static_cast<uint32_t>(g_bulk_pa >> 32),
	    static_cast<uint32_t>(g_bulk_pa), 0, nullptr);
	if (status != 0) {
		log_cdc("NABU USB CDCLOG bulk-cmd=%d\n", status);
		return;
	}
	g_bulk_busy = true;
	g_bulk_len = n;
	g_bulk_rsc = g_resources[3];
}

static void
bulk_complete(void)
{
	if (!g_bulk_busy) {
		return;
	}
	const uint32_t status = mrd(g_bulk, 8);
	const uint32_t remaining = status & kTrbSizeMask;
	const unsigned sent = remaining <= g_bulk_len ?
	    g_bulk_len - remaining : 0;
	g_log_cursor += sent;
	g_log_sent += sent;
	g_bulk_busy = false;
	log_cdc("NABU USB CDCLOG bulk-done sent=%u status=%08x\n", sent, status);
}

static void
handle_dep_event(uint32_t ev)
{
	const unsigned dep = (ev >> 1) & 0x1fu;
	const unsigned kind = (ev >> 6) & 0xfu;
	const unsigned status = (ev >> 12) & 0xfu;

	if (kind == kDepevtXferNotReady) {
		if (dep <= 1 && status == kDepevtStatusControlStatus &&
		    dep == g_ep0_status_dep && g_ep0_state == kEp0WaitStatus) {
			log_cdc("NABU USB CDCLOG status-ready dep=%u\n", dep);
			ep0_status(dep <= 1 ? dep : g_ep0_status_dep);
		}
		return;
	}
	if (kind != kDepevtXferComplete) {
		return;
	}
	if (dep == 3) {
		g_resources[3] = 0;
		bulk_complete();
		return;
	}
	if (dep > 1) {
		return;
	}
	g_resources[dep] = 0;
	if (g_ep0_state == kEp0Setup && dep == 0) {
		ep0_setup();
		return;
	}
	if (g_ep0_state == kEp0Data) {
		if (dep != g_ep0_data_dep) {
			log_cdc("NABU USB CDCLOG data-dep-mismatch dep=%u want=%u\n",
			    dep, g_ep0_data_dep);
		}
		const uint32_t last = mrd(ep0_trb(g_ep0_trbs - 1), 2);
		const unsigned trbsts = (last & kTrbSizeTrbstsMask) >>
		    kTrbSizeTrbstsShift;
		if (trbsts == kTrbstsSetupPending) {
			puts_cdc("NABU USB CDCLOG setup-pending\n");
			ep0_arm_setup();
			return;
		}
		if (g_ep0_zlp) {
			g_ep0_zlp = false;
			ep0_data(1, kEp0Stage, 0);
			return;
		}
		g_ep0_state = kEp0WaitStatus;
		return;
	}
	if (g_ep0_state == kEp0Status) {
		puts_cdc("NABU USB CDCLOG status-done\n");
		ep0_arm_setup();
		return;
	}
}

static void
handle_device_event(uint32_t ev)
{
	const unsigned type = (ev >> 8) & 0xfu;
	const unsigned info = (ev >> 16) & 0x1ffu;
	log_cdc("NABU USB CDCLOG devt type=%u info=%03x\n", type, info);
	if (type == kDevEventReset) {
		/* Linux dwc3_gadget_reset_interrupt: end active transfers, put
		 * EP0 back into setup phase, clear test mode and the device
		 * address, then re-arm SETUP. */
		ep_end_transfer(0, 0);
		ep_end_transfer(1, 0);
		if (g_bulk_busy) {
			ep_end_transfer(3, g_bulk_rsc);
		}
		(void)ep_cmd(0, kDepcmdSetStall, 0, 0, 0, nullptr);
		(void)ep_cmd(0, kDepcmdClearStall, 0, 0, 0, nullptr);
		uint32_t dctl = mrd(g_regs, kDwc3Dctl);
		mwr(g_regs, kDwc3Dctl, dctl & ~kDctlTstctrlMask);
		uint32_t dcfg = mrd(g_regs, kDwc3Dcfg);
		dcfg &= ~kDcfgDevaddrMask;
		mwr(g_regs, kDwc3Dcfg, dcfg);
		g_configured = 0;
		g_bulk_enabled = false;
		g_bulk_busy = false;
		disable_data_endpoints();
		g_data_eps_programmed = false;
		ep0_arm_setup();
	} else if (type == kDevEventConnectDone) {
		const unsigned speed = mrd(g_regs, kDwc3Dsts) & kDstsConnectspdMask;
		if (speed != kDcfgHighSpeed) {
			log_cdc("NABU USB CDCLOG verdict=unsupported-link-speed speed=%u\n", speed);
			g_faulted = true;
			return;
		}
		uint32_t dcfg = mrd(g_regs, kDwc3Dcfg);
		dcfg &= ~kDcfgSpeedMask;
		dcfg |= kDcfgHighSpeed;
		mwr(g_regs, kDwc3Dcfg, dcfg);
		log_cdc("NABU USB CDCLOG connect speed=%u dsts=%08x\n",
		    mrd(g_regs, kDwc3Dsts) & kDstsConnectspdMask,
		    mrd(g_regs, kDwc3Dsts));
	} else if (type == kDevEventDisconnect) {
		g_bulk_busy = false;
		g_bulk_enabled = false;
		g_configured = 0;
		disable_data_endpoints();
	}
}

static void
poll_events(void)
{
	for (unsigned guard = 0; guard < 64; ++guard) {
		const uint32_t count = mrd(g_regs, kDwc3Gevntcount) &
		    kGevntcountMask;
		if (count == 0) {
			return;
		}
		if (count > 4096u) {
			/* The core wrapped the whole ring; nothing left to resync. */
			g_evt_cursor = (g_evt_cursor + count) % 4096u;
			mwr(g_regs, kDwc3Gevntcount, count);
			continue;
		}
		unsigned left = count;
		while (left >= 4) {
			const uint32_t ev = mrd(g_evt, g_evt_cursor);
			++g_events;
			if (ev & 1u) {
				handle_device_event(ev);
			} else {
				handle_dep_event(ev);
			}
			if (g_faulted) {
				return;
			}
			g_evt_cursor = (g_evt_cursor + 4u) % 4096u;
			left -= 4;
		}
		mwr(g_regs, kDwc3Gevntcount, count);
	}
}

/* ------------------------------------------------------------------------- */
/* SMMU and DMA                                                              */
/* ------------------------------------------------------------------------- */
static bool
smmu_configure(void)
{
	g_smmu = reinterpret_cast<volatile uint32_t *>(
	    ml_io_map(static_cast<vm_offset_t>(nabu_usb::smmu::kBase),
	    static_cast<vm_size_t>(nabu_usb::smmu::kWindow)));
	if (g_smmu == nullptr) {
		puts_cdc("NABU USB CDCLOG smmu=map-fail\n");
		return false;
	}
	auto read = [](uint32_t off) -> uint32_t {
		return mrd(g_smmu, off);
	};
	nabu_usb::smmu::Info info;
	if (!nabu_usb::smmu::read_info(read, &info)) {
		log_cdc("NABU USB CDCLOG smmu=unsupported idr0=%08x idr1=%08x idr2=%08x\n",
		    mrd(g_smmu, nabu_usb::smmu::kIdr0),
		    mrd(g_smmu, nabu_usb::smmu::kIdr1),
		    mrd(g_smmu, nabu_usb::smmu::kIdr2));
		return false;
	}
	log_cdc("NABU USB CDCLOG smmu idr0=%08x gfsr=%08x numsmr=%u numcb=%u pages=%u\n",
	    info.idr0, info.gfsr, info.num_smr, info.num_cb, info.global_pages);
	const nabu_usb::smmu::Plan plan =
	    nabu_usb::smmu::plan_bypass(read, info, 0x140u);
	if (!plan.valid) {
		log_cdc("NABU USB CDCLOG smmu plan=%s\n", plan.error);
		return false;
	}
	log_cdc("NABU USB CDCLOG smmu plan slot=%u bank=%u reuse=%u\n",
	    plan.index, plan.bank, plan.reuse ? 1u : 0u);
	auto write = [](uint32_t off, uint32_t value) {
		mwr(g_smmu, off, value);
		mmio_barrier();
	};
	if (!nabu_usb::smmu::configure_bypass(read, write, plan, 0x140u)) {
		puts_cdc("NABU USB CDCLOG smmu=configure-failed\n");
		return false;
	}
	return true;
}

static bool
dma_block(uint8_t *va, uint32_t size, volatile uint32_t **out, uint64_t *pa)
{
	const uint64_t phys = ml_vtophys(reinterpret_cast<vm_offset_t>(va));
	if (phys == 0 || (phys & 0xfffu) != 0) {
		return false;
	}
	const vm_offset_t io = ml_io_map(static_cast<vm_offset_t>(phys),
	    static_cast<vm_size_t>(size));
	if (io == 0) {
		return false;
	}
	/* The cacheable BSS alias was zeroed by the kernel; remove any dirty or
	 * stale line before the controller becomes the owner. */
	FlushPoC_DcacheRegion(reinterpret_cast<vm_offset_t>(va), size);
	*out = reinterpret_cast<volatile uint32_t *>(io);
	*pa = phys;
	return true;
}

static bool
dma_setup(void)
{
	if (!dma_block(g_event_block, sizeof(g_event_block), &g_evt, &g_event_pa) ||
	    !dma_block(g_ep0_block, sizeof(g_ep0_block), &g_ep0, &g_ep0_pa) ||
	    !dma_block(g_bulk_block, sizeof(g_bulk_block), &g_bulk, &g_bulk_pa)) {
		puts_cdc("NABU USB CDCLOG dma=map-fail\n");
		return false;
	}
	const uint32_t awidth = (mrd(g_regs, kDwc3Ghwparams0) &
	    kGhwparams0AwidthMask) >> kGhwparams0AwidthShift;
	log_cdc("NABU USB CDCLOG dma evt=%llx ep0=%llx bulk=%llx awidth=%u\n",
	    static_cast<unsigned long long>(g_event_pa),
	    static_cast<unsigned long long>(g_ep0_pa),
	    static_cast<unsigned long long>(g_bulk_pa), awidth);
	if (awidth < 32 || awidth > 64) {
		puts_cdc("NABU USB CDCLOG dma=bad-awidth\n");
		return false;
	}
	const uint64_t limit = awidth == 64 ? ~0ull : ((1ull << awidth) - 1ull);
	if ((g_event_pa | g_ep0_pa | g_bulk_pa) > limit) {
		puts_cdc("NABU USB CDCLOG dma=above-awidth\n");
		return false;
	}
	return true;
}

/* ------------------------------------------------------------------------- */
/* Stop and pump                                                             */
/* ------------------------------------------------------------------------- */
static void
usb_stop(void)
{
	if (g_regs != nullptr) {
		mwr(g_regs, kDwc3Devten, 0);
		mwr(g_regs, kDwc3Gevten, 0);
		if (g_bulk_busy) {
			ep_end_transfer(3, g_bulk_rsc);
			g_bulk_busy = false;
		}
		const uint32_t dctl = mrd(g_regs, kDwc3Dctl);
		mwr(g_regs, kDwc3Dctl, dctl & ~kDctlRunStop);
		(void)wait_mask(g_regs, kDwc3Dsts, kDstsDevctrlhlt,
		    kDstsDevctrlhlt, 20000);
	}
	log_cdc("NABU USB CDCLOG stopped events=%u setups=%u sent=%llu dropped=%llu\n",
	    g_events, g_setups, g_log_sent, g_log_dropped);
}

static void
pump(unsigned rounds)
{
	for (unsigned round = 0; round < rounds && !g_faulted; ++round) {
		IOSleep(2);
		poll_events();
		bulk_pump();
		if ((round % 4000u) == 0) {
			log_cdc("NABU USB CDCLOG round=%u events=%u setups=%u sent=%llu\n",
			    round, g_events, g_setups, g_log_sent);
		}
	}
}

} // namespace

/* Runs on an ordinary thread; the bsd_init hook only creates it. */
static void
usb_run(void)
{
	int enabled = 0;
	if (!PE_parse_boot_argn("nabu-usb-cdc-log", &enabled, sizeof(enabled)) ||
	    enabled != 1) {
		return;
	}
	puts_cdc("NABU USB CDCLOG v1 start\n");

	int init = 0;
	int allow_smmu = 0;
	unsigned rounds = 20000;
	(void)PE_parse_boot_argn("nabu-usb-cdc-log-init", &init, sizeof(init));
	(void)PE_parse_boot_argn("nabu-usb-cdc-log-smmu", &allow_smmu,
	    sizeof(allow_smmu));
	if (!PE_parse_boot_argn("nabu-usb-cdc-log-rounds", &rounds,
	    sizeof(rounds)) || rounds > 60000u) {
		rounds = 20000u;
	}

	if (!gcc_gate_readonly()) {
		return;
	}
	g_regs = reinterpret_cast<volatile uint32_t *>(
	    ml_io_map(static_cast<vm_offset_t>(kDwc3Base),
	    static_cast<vm_size_t>(kDwc3Size)));
	if (g_regs == nullptr) {
		puts_cdc("NABU USB CDCLOG dwc3=map-fail\n");
		return;
	}
	const uint32_t id = mrd(g_regs, kDwc3Gsnpsid);
	const uint32_t family = id & kGsnpsidMask;
	log_cdc("NABU USB CDCLOG id=%08x dcfg=%08x dctl=%08x dsts=%08x gctl=%08x\n",
	    id, mrd(g_regs, kDwc3Dcfg), mrd(g_regs, kDwc3Dctl),
	    mrd(g_regs, kDwc3Dsts), mrd(g_regs, kDwc3Gctl));
	if (family != kGsnpsidDwcUsb3 && family != kGsnpsidDwcUsb31 &&
	    family != kGsnpsidDwcUsb31_3331) {
		log_cdc("NABU USB CDCLOG verdict=id-invalid id=%08x\n", id);
		return;
	}
	if (!init) {
		puts_cdc("NABU USB CDCLOG verdict=read-ok-init-off\n");
		return;
	}

	if (!allow_smmu) {
		puts_cdc("NABU USB CDCLOG verdict=stopped-before-dma smmu=off\n");
		return;
	}
	g_phy = reinterpret_cast<volatile uint32_t *>(ml_io_map(kHsPhyBase, kHsPhySize));
	if (g_phy == nullptr) {
		puts_cdc("NABU USB CDCLOG verdict=phy-map-fail\n");
		return;
	}
	mwr(g_phy, kPhyCommon1, mrd(g_phy, kPhyCommon1) | kPhyVbusSelect);
	mwr(g_phy, kPhyCtrl1, mrd(g_phy, kPhyCtrl1) | kPhyVbusValid);
	if (!(mrd(g_phy, kPhyCommon1) & kPhyVbusSelect) ||
	    !(mrd(g_phy, kPhyCtrl1) & kPhyVbusValid)) {
		puts_cdc("NABU USB CDCLOG verdict=phy-vbus-readback\n");
		return;
	}
	qscratch_clocks();
	if (!core_init()) {
		return;
	}
	if (!smmu_configure()) {
		puts_cdc("NABU USB CDCLOG verdict=stopped-before-dma smmu=refused\n");
		return;
	}
	if (!dma_setup()) {
		puts_cdc("NABU USB CDCLOG verdict=stopped-before-dma dma=bad\n");
		return;
	}
	event_program();
	ep0_program();
	ep0_arm_setup();
	if (g_faulted) {
		usb_stop();
		return;
	}
	qscratch_vbus();

	uint32_t dctl = mrd(g_regs, kDwc3Dctl);
	dctl |= kDctlRunStop;
	dctl &= ~kDctlHirdThresMask;
	dctl |= kDctlHirdThres;
	mwr(g_regs, kDwc3Dctl, dctl);
	log_cdc("NABU USB CDCLOG run dctl=%08x dsts=%08x\n",
	    mrd(g_regs, kDwc3Dctl), mrd(g_regs, kDwc3Dsts));

	pump(rounds);
	usb_stop();
}

static void
usb_worker(void *, wait_result_t)
{
	usb_run();
	thread_terminate(current_thread());
}

extern "C" void
nabu_usb_cdc_log_start(void)
{
	int enabled = 0;
	if (!PE_parse_boot_argn("nabu-usb-cdc-log", &enabled, sizeof(enabled)) ||
	    enabled != 1) {
		return;
	}
	bool expected = false;
	if (!__atomic_compare_exchange_n(&g_started, &expected, true, false,
	    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		return;
	}
	thread_t thread = THREAD_NULL;
	if (kernel_thread_start(usb_worker, nullptr, &thread) == KERN_SUCCESS) {
		thread_deallocate(thread);
	} else {
		g_started = false;
		puts_cdc("NABU USB CDCLOG verdict=thread-start-fail\n");
	}
}

} // namespace nabu_usb_capture