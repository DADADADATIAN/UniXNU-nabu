// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Opt-in, read-only snapshot of the SM8150 USB controller state at bsd_init.
//
// This file performs no MMIO writes. It answers one question before any log
// pump is written: after the bootloader hand-off, are the USB30_PRIM power
// domain, its GCC branch clocks and the DWC3 core registers already usable,
// and does apps-SMMU already carry the USB stream (SID 0x140)?
//
// v2 (2026-10-26): the first hardware run stopped after the SMMU IDR0/GFSR
// read, i.e. on the first SMR access. The SID scan therefore needs a second
// boot argument (nabu-usb-probe-smr=1); by default the probe prints
// sid140=scan-disabled and continues. Stage markers bracket each MMIO region so
// the next hang names its own register block, and the DWC3 wrapper (QSCRATCH)
// is read before the core so wrapper and core accessibility are distinguishable.
//
// v3 (2026-10-26): the opt-in scan now takes its length from IDR0.NUMSMRG
// (bits[7:0], 94 on this board; 0x4c017e5e). Reads above the implemented
// count are now excluded; the v1 stall location remains unproven. SID matching is mask aware: SMR.MASK is bits[30:16] (SMMUv2, Linux
// arm-smmu.h), so (SID ^ SMR.ID) & ~MASK must be zero. S2CR TYPE is decoded
// from bits[17:16] (TRANS=0, BYPASS=1, FAULT=2), not the low two bits.
//
// Gate: boot-arg nabu-usb-probe=1. Absent or any other value: no MMIO access.
// The probe is linked only into NABU_CAPTURE_LOG builds; the call site is
// injected by nabu_capture_source.py next to the other opt-in console hooks.

#include <IOKit/IOLib.h>
#include <pexpert/pexpert.h>
#include <vm/pmap.h>

#include "../usb/NabuUsbSmmu.h"

extern "C" vm_offset_t ml_io_map(vm_offset_t pa, vm_size_t size);
extern "C" void nabu_usb_probe_start(void);

namespace {

// SM8150 block geometry. GCC offsets are from the nabu board DT
// (clock-controller@100000) and gcc-sm8150.c; DWC3/QSCRATCH match the
// dwc-usb3-msm wrapper at 0x0a600000 used by the XBL fastboot path.
constexpr uint64_t kGccPa = 0x00100000ull;
constexpr uint32_t kGccSize = 0x00090000u;
constexpr uint64_t kDwc3Pa = 0x0a600000ull;
constexpr uint32_t kDwc3Size = 0x00100000u;
constexpr uint32_t kQscratch = 0x000f8800u;
constexpr uint64_t kSmmuPa = 0x15000000ull;
constexpr uint32_t kSmmuSize = 0x00008000u;

constexpr uint32_t kUsbSid = 0x140u;

// GCC USB30_PRIM / QUSB2 references (read-only in this probe).
constexpr uint32_t kGdscr = 0x0f004u;       // bit31 PWR_ON, bit0 SW_COLLAPSE
constexpr uint32_t kMasterClk = 0x0f010u;   // bit31 CLK_OFF
constexpr uint32_t kSleepClk = 0x0f014u;
constexpr uint32_t kMockUtmiClk = 0x0f018u;
constexpr uint32_t kCfgNocClk = 0x0f078u;
constexpr uint32_t kAggreClk = 0x0f07cu;
constexpr uint32_t kRefPrimClk = 0x8c008u;
constexpr uint32_t kRefSecClk = 0x8c028u;

// DWC3 global/device registers.
constexpr uint32_t kGsnpsid = 0xc120u;
constexpr uint32_t kGhwparams0 = 0xc140u;
constexpr uint32_t kGhwparams1 = 0xc144u;
constexpr uint32_t kGhwparams2 = 0xc148u;
constexpr uint32_t kGhwparams3 = 0xc14cu;
constexpr uint32_t kGhwparams4 = 0xc150u;
constexpr uint32_t kGhwparams6 = 0xc158u;
constexpr uint32_t kGctl = 0xc110u;
constexpr uint32_t kGusb2phycfg0 = 0xc200u;
constexpr uint32_t kGusb3pipectl0 = 0xc2c0u;
constexpr uint32_t kGevntsiz0 = 0xc408u;
constexpr uint32_t kGevntcount0 = 0xc40cu;
constexpr uint32_t kDcfg = 0xc700u;
constexpr uint32_t kDctl = 0xc704u;
constexpr uint32_t kDevten = 0xc708u;
constexpr uint32_t kDsts = 0xc70cu;
constexpr uint32_t kDalepena = 0xc720u;

// QSCRATCH register offsets inside the dwc-usb3-msm wrapper.
constexpr uint32_t kQGeneralCfg = 0x08u;
constexpr uint32_t kQHsPhyCtrl = 0x10u;
constexpr uint32_t kQCgctl = 0x28u;
constexpr uint32_t kQSsPhyCtrl = 0x30u;
constexpr uint32_t kQPwrEvtStat = 0x58u;

// ARM SMMUv2 register windows used for the read-only stream check.
constexpr uint32_t kSmmuIdr0 = 0x0020u;
constexpr uint32_t kSmmuIdr1 = 0x0024u;
constexpr uint32_t kSmmuIdr2 = 0x0028u;
constexpr uint32_t kSmmuGfsr = 0x0048u;

struct ClockGate {
	const char *name;
	uint32_t offset;
};

const ClockGate kClockGates[] = {
	{ "master", kMasterClk },
	{ "sleep", kSleepClk },
	{ "mock", kMockUtmiClk },
	{ "cfg-noc", kCfgNocClk },
	{ "aggre", kAggreClk },
};

uint32_t
read32(vm_offset_t base, uint32_t offset)
{
	uint32_t value = *(volatile uint32_t *)(base + offset);
#if defined(__aarch64__)
	__asm__ volatile ("dmb oshld" ::: "memory");
#endif
	return value;
}

// No serial console is reachable on this device: hold the snapshot on the
// framebuffer long enough to photograph, then let the boot continue. This is a
// kernel sleep, not an MMIO access or a bus wait.
void
probe_hold(void)
{
	IOSleep(90000);
}

void
probe_smmu(void)
{
	vm_offset_t smmu = ml_io_map((vm_offset_t)kSmmuPa, (vm_size_t)kSmmuSize);
	if (smmu == 0) {
		IOLog("NABU USB PROBE smmu map=FAIL\n");
		return;
	}
	uint32_t idr0 = read32(smmu, kSmmuIdr0);
	uint32_t gfsr = read32(smmu, kSmmuGfsr);
	IOLog("NABU USB PROBE smmu idr0=%08x gfsr=%08x\n", idr0, gfsr);
	// The first hardware run stopped on the first SMR read right after the
	// line above. Keep the scan behind an explicit second argument until the
	// SMMU register-bank clock is understood; IDR0/GFSR are known readable.
	int scan = 0;
	if (!PE_parse_boot_argn("nabu-usb-probe-smr", &scan, sizeof(scan)) ||
	    scan != 1) {
		IOLog("NABU USB PROBE smmu sid140=scan-disabled\n");
		return;
	}
	// Authoritative SMMUv2 interpretation from NabuUsbSmmu.h.  NUMSMRG is
	// IDR0[7:0] (a count), matching is mask-aware, and S2CR TYPE lives at
	// bits[17:16]; bits[1:0] are CBNDX, not TYPE (the archive's error).
	auto read = [smmu](uint32_t offset) {
		return read32(smmu, offset);
	};
	nabu_usb::smmu::Info info;
	if (!nabu_usb::smmu::read_info(read, &info)) {
		IOLog("NABU USB PROBE smmu decode=unsupported idr1=%08x idr2=%08x numsmr=%u\n",
		    read32(smmu, kSmmuIdr1), read32(smmu, kSmmuIdr2),
		    idr0 & 0xffu);
		return;
	}
	IOLog("NABU USB PROBE smmu numsmr=%u numcb=%u pages=%u\n",
	    info.num_smr, info.num_cb, info.global_pages);
	nabu_usb::smmu::Match match;
	if (!nabu_usb::smmu::find_stream(read, info, kUsbSid, &match)) {
		IOLog("NABU USB PROBE smmu sid140=absent\n");
		return;
	}
	IOLog("NABU USB PROBE smmu sid140 index=%u smr=%08x s2cr=%08x type=%u cbndx=%u mask=%04x\n",
	    match.index, match.smr, match.s2cr, match.type, match.cbndx,
	    match.mask);
}

} // namespace

extern "C" void
nabu_usb_probe_start(void)
{
	int enabled = 0;

	if (!PE_parse_boot_argn("nabu-usb-probe", &enabled, sizeof(enabled)) ||
	    enabled != 1) {
		return;
	}

	IOLog("NABU USB PROBE v3 start\n");

	vm_offset_t gcc = ml_io_map((vm_offset_t)kGccPa, (vm_size_t)kGccSize);
	if (gcc == 0) {
		IOLog("NABU USB PROBE verdict=gcc-map-fail\n");
		probe_hold();
		return;
	}
	uint32_t gdscr = read32(gcc, kGdscr);
	IOLog("NABU USB PROBE gcc gdscr=%08x pwr=%u collapse=%u\n",
	    gdscr, (gdscr >> 31) & 1u, gdscr & 1u);
	if ((gdscr & 0x80000000u) == 0) {
		IOLog("NABU USB PROBE verdict=gdsc-pwr-off\n");
		probe_hold();
		return;
	}

	unsigned halted = 0;
	for (unsigned i = 0; i < sizeof(kClockGates) / sizeof(kClockGates[0]); ++i) {
		uint32_t value = read32(gcc, kClockGates[i].offset);
		if (value & 0x80000000u) {
			++halted;
		}
		IOLog("NABU USB PROBE gcc %s=%08x halt=%u en=%u\n",
		    kClockGates[i].name, value, (value >> 31) & 1u, value & 1u);
	}
	IOLog("NABU USB PROBE gcc refprim=%08x refsec=%08x\n",
	    read32(gcc, kRefPrimClk), read32(gcc, kRefSecClk));
	IOLog("NABU USB PROBE stage=smmu-id\n");
	probe_smmu();

	if (halted != 0) {
		// Reading a halted core can hang the interconnect; stop here and let
		// the next candidate add the clock bring-up instead.
		IOLog("NABU USB PROBE verdict=clocks-halted halted=%u\n", halted);
		probe_hold();
		return;
	}

	vm_offset_t dwc = ml_io_map((vm_offset_t)kDwc3Pa, (vm_size_t)kDwc3Size);
	if (dwc == 0) {
		IOLog("NABU USB PROBE verdict=dwc3-map-fail\n");
		probe_hold();
		return;
	}

	// Wrapper first: QSCRATCH lives in the dwc-usb3-msm wrapper. If it is
	// already readable the block's AHB path is clocked, and a later stop
	// isolates the core register access instead of the wrapper transport.
	IOLog("NABU USB PROBE stage=qscratch\n");
	uint32_t qgen = read32(dwc, kQscratch + kQGeneralCfg);
	uint32_t qhsphy = read32(dwc, kQscratch + kQHsPhyCtrl);
	IOLog("NABU USB PROBE qscratch-early general=%08x hsphy=%08x\n",
	    qgen, qhsphy);
	IOLog("NABU USB PROBE stage=dwc3-core\n");
	uint32_t sid = read32(dwc, kGsnpsid);
	IOLog("NABU USB PROBE id=%08x family=%04x rev=%04x\n",
	    sid, (sid >> 16) & 0xffffu, sid & 0xffffu);
	IOLog("NABU USB PROBE hwparams=%08x,%08x,%08x,%08x,%08x,%08x\n",
	    read32(dwc, kGhwparams0), read32(dwc, kGhwparams1),
	    read32(dwc, kGhwparams2), read32(dwc, kGhwparams3),
	    read32(dwc, kGhwparams4), read32(dwc, kGhwparams6));

	uint32_t gctl = read32(dwc, kGctl);
	uint32_t dcfg = read32(dwc, kDcfg);
	uint32_t dctl = read32(dwc, kDctl);
	uint32_t dsts = read32(dwc, kDsts);
	IOLog("NABU USB PROBE gctl=%08x prtcap=%u gusb2phycfg=%08x gusb3pipectl=%08x\n",
	    gctl, (gctl >> 12) & 3u, read32(dwc, kGusb2phycfg0),
	    read32(dwc, kGusb3pipectl0));
	IOLog("NABU USB PROBE dcfg=%08x devspd=%u dctl=%08x runstop=%u devten=%08x\n",
	    dcfg, dcfg & 7u, dctl, (dctl >> 31) & 1u, read32(dwc, kDevten));
	IOLog("NABU USB PROBE dsts=%08x connectspeed=%u halted=%u dalepena=%08x\n",
	    dsts, dsts & 7u, (dsts >> 22) & 1u, read32(dwc, kDalepena));
	IOLog("NABU USB PROBE gevntsiz=%08x gevntcount=%08x\n",
	    read32(dwc, kGevntsiz0), read32(dwc, kGevntcount0));

	// QSCRATCH reads are only safe once the core clocks are running.
	uint32_t hsphy = read32(dwc, kQscratch + kQHsPhyCtrl);
	IOLog("NABU USB PROBE qscratch general=%08x hsphy=%08x cgctl=%08x ssphy=%08x pwrevt=%08x\n",
	    read32(dwc, kQscratch + kQGeneralCfg), hsphy,
	    read32(dwc, kQscratch + kQCgctl),
	    read32(dwc, kQscratch + kQSsPhyCtrl),
	    read32(dwc, kQscratch + kQPwrEvtStat));
	IOLog("NABU USB PROBE qscratch vbus-valid=%u sessvld-sel=%u utmi-clk-dis=%u\n",
	    (hsphy >> 20) & 1u, (hsphy >> 28) & 1u,
	    (read32(dwc, kQscratch + kQGeneralCfg) >> 8) & 1u);

	if (sid == 0 || sid == 0xffffffffu) {
		IOLog("NABU USB PROBE verdict=id-invalid id=%08x\n", sid);
		probe_hold();
		return;
	}
	IOLog("NABU USB PROBE verdict=read-ok\n");
	probe_hold();
}
