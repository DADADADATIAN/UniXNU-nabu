/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Register and descriptor constants for the capture-ring CDC channel.
 * Kept in a separate header from the other USB work in this directory so the
 * two implementations can be reviewed independently.  Numbering follows the
 * Synopsys DWC_usb3/usb31 programming model as encoded by Linux v6.17
 * drivers/usb/dwc3/{core.h,gadget.h,ep0.c} and the SM8150 GCC map used by the
 * nabu board tree.  No MMIO helper and no write path lives here.
 */
#ifndef NABU_USB_CAPTURE_REGS_H
#define NABU_USB_CAPTURE_REGS_H

#include <stdint.h>

namespace nabu_usb_capture {

/* nabu device-tree geometry. */
constexpr uint64_t kGccBase = 0x00100000ull;
constexpr uint32_t kGccSize = 0x00090000u;
constexpr uint64_t kDwc3Base = 0x0a600000ull;
constexpr uint32_t kDwc3Size = 0x00100000u;
constexpr uint64_t kHsPhyBase = 0x088e2000ull;
constexpr uint32_t kHsPhySize = 0x1000u;
constexpr uint32_t kPhyCommon1 = 0x58u;
constexpr uint32_t kPhyCtrl1 = 0x60u;
constexpr uint32_t kPhyVbusSelect = 1u << 4;
constexpr uint32_t kPhyVbusValid = 1u;
constexpr uint32_t kQscratch = 0x000f8800u;

/* GCC USB30_PRIM power domain and branch clocks (read-only here). */
constexpr uint32_t kGccGdscr = 0x000f004u;
constexpr uint32_t kGccMasterClk = 0x000f010u;
constexpr uint32_t kGccSleepClk = 0x000f014u;
constexpr uint32_t kGccMockUtmiClk = 0x000f018u;
constexpr uint32_t kGccCfgNocClk = 0x000f078u;
constexpr uint32_t kGccAggreClk = 0x000f07cu;
constexpr uint32_t kGccGdscrPwrOn = 1u << 31;
constexpr uint32_t kGccBranchClkOff = 1u << 31;

/* DWC3 global registers. */
constexpr uint32_t kDwc3Gctl = 0x0000c110u;
constexpr uint32_t kDwc3Gevten = 0x0000c114u;
constexpr uint32_t kDwc3Gsnpsid = 0x0000c120u;
constexpr uint32_t kDwc3Ghwparams0 = 0x0000c140u;
constexpr uint32_t kDwc3Gusb2phycfg0 = 0x0000c200u;
constexpr uint32_t kDwc3Gusb3pipectl0 = 0x0000c2c0u;
constexpr uint32_t kDwc3Gevntadrlo = 0x0000c400u;
constexpr uint32_t kDwc3Gevntadrhi = 0x0000c404u;
constexpr uint32_t kDwc3Gevntsiz = 0x0000c408u;
constexpr uint32_t kDwc3Gevntcount = 0x0000c40cu;
constexpr uint32_t kDwc3Dcfg = 0x0000c700u;
constexpr uint32_t kDwc3Dctl = 0x0000c704u;
constexpr uint32_t kDwc3Devten = 0x0000c708u;
constexpr uint32_t kDwc3Dsts = 0x0000c70cu;
constexpr uint32_t kDwc3Dalepena = 0x0000c720u;

/* Endpoint n command block: PAR2, PAR1, PAR0, CMD at 0xc800 + 0x10*n. */
static inline uint32_t
depcmdpar2(unsigned dep)
{
	return 0x0000c800u + 0x10u * dep;
}
static inline uint32_t
depcmdpar1(unsigned dep)
{
	return 0x0000c804u + 0x10u * dep;
}
static inline uint32_t
depcmdpar0(unsigned dep)
{
	return 0x0000c808u + 0x10u * dep;
}
static inline uint32_t
depcmd(unsigned dep)
{
	return 0x0000c80cu + 0x10u * dep;
}

/* GCTL */
constexpr uint32_t kGctlCoresoftreset = 1u << 11;
constexpr uint32_t kGctlPrtcapdirShift = 12;
constexpr uint32_t kGctlPrtcapdirMask = 0x3u << kGctlPrtcapdirShift;
constexpr uint32_t kGctlPrtcapDevice = 2u;
constexpr uint32_t kGctlDsblclkgtng = 1u << 0;

/* GUSB2PHYCFG / GUSB3PIPECTL */
constexpr uint32_t kGusb2phycfgPhysftrst = 1u << 31;
constexpr uint32_t kGusb2phycfgSusphy = 1u << 6;
constexpr uint32_t kGusb2phycfgEnblslpm = 1u << 8;
constexpr uint32_t kGusb3pipectlSusphy = 1u << 17;

/* DCTL / DCFG / DSTS */
constexpr uint32_t kDctlRunStop = 1u << 31;
constexpr uint32_t kDctlCsftrst = 1u << 30;
constexpr uint32_t kDctlHirdThresMask = 0x1fu << 24;
constexpr uint32_t kDctlHirdThres = 0x10u << 24;
constexpr uint32_t kDctlTstctrlMask = 0x0fu << 1;
constexpr uint32_t kDcfgSpeedMask = 0x7u;
constexpr uint32_t kDcfgHighSpeed = 0u;
constexpr uint32_t kDcfgDevaddrShift = 3;
constexpr uint32_t kDcfgDevaddrMask = 0x7fu << kDcfgDevaddrShift;
constexpr uint32_t kDstsConnectspdMask = 0x7u;
constexpr uint32_t kDstsDevctrlhlt = 1u << 22;

/* DEVTEN / GEVTEN / event buffer */
constexpr uint32_t kDevtenBasic = (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3);
constexpr uint32_t kGevtenEnable = 1u << 0;
constexpr uint32_t kGevntsizSizeMask = 0xffffu;
constexpr uint32_t kGevntcountMask = 0xfffcu;

/* GSNPSID families accepted on this board. */
constexpr uint32_t kGsnpsidMask = 0xffff0000u;
constexpr uint32_t kGsnpsidDwcUsb3 = 0x55330000u;
constexpr uint32_t kGsnpsidDwcUsb31 = 0x55340000u;
constexpr uint32_t kGsnpsidDwcUsb31_3331 = 0x33310000u;

/* GHWPARAMS0 address width (address bits). */
constexpr uint32_t kGhwparams0AwidthShift = 24;
constexpr uint32_t kGhwparams0AwidthMask = 0xffu << kGhwparams0AwidthShift;

/* DEPCMD */
constexpr uint32_t kDepcmdStatusShift = 12;
constexpr uint32_t kDepcmdStatusMask = 0xfu << kDepcmdStatusShift;
constexpr uint32_t kDepcmdCmdact = 1u << 10;
constexpr uint32_t kDepcmdCmdioc = 1u << 8;
constexpr uint32_t kDepcmdParamShift = 16;
constexpr uint32_t kDepcmdSetEpConfig = 0x01u;
constexpr uint32_t kDepcmdSetTransferResource = 0x02u;
constexpr uint32_t kDepcmdSetStall = 0x04u;
constexpr uint32_t kDepcmdClearStall = 0x05u;
constexpr uint32_t kDepcmdStartTransfer = 0x06u;
constexpr uint32_t kDepcmdEndTransfer = 0x08u;
constexpr uint32_t kDepcmdDepStartCfg = 0x09u;

/* DEPCFG */
constexpr uint32_t kDepcfgEpTypeShift = 1;
constexpr uint32_t kDepcfgMaxPacketShift = 3;
constexpr uint32_t kDepcfgFifoShift = 17;
constexpr uint32_t kDepcfgActionInit = 0u;
constexpr uint32_t kDepcfgActionModify = 2u << 30;
constexpr uint32_t kDepcfgXferCompleteEn = 1u << 8;
constexpr uint32_t kDepcfgXferInProgressEn = 1u << 9;
constexpr uint32_t kDepcfgXferNotReadyEn = 1u << 10;
constexpr uint32_t kDepcfgEpNumberShift = 25;
constexpr uint32_t kDepxfercfgNumXferResMask = 0xffffu;
constexpr uint32_t kEpTypeControl = 0u;
constexpr uint32_t kEpTypeBulk = 2u;
constexpr uint32_t kEpTypeInterrupt = 3u;

static inline uint32_t
dalepena_ep(unsigned dep)
{
	return 1u << dep;
}

/* TRB control */
constexpr uint32_t kTrbCtrlHwo = 1u << 0;
constexpr uint32_t kTrbCtrlLst = 1u << 1;
constexpr uint32_t kTrbCtrlChn = 1u << 2;
constexpr uint32_t kTrbCtrlTrbctlShift = 4;
constexpr uint32_t kTrbCtrlIspImi = 1u << 10;
constexpr uint32_t kTrbCtrlIoc = 1u << 11;
constexpr uint32_t kTrbSizeMask = 0x00ffffffu;
constexpr uint32_t kTrbSizeTrbstsShift = 28;
constexpr uint32_t kTrbSizeTrbstsMask = 0xfu << kTrbSizeTrbstsShift;
constexpr uint32_t kTrbstsSetupPending = 2u;
static constexpr uint32_t
trbctl(uint32_t type)
{
	return (type & 0x3fu) << kTrbCtrlTrbctlShift;
}
constexpr uint32_t kTrbctlNormal = trbctl(1);
constexpr uint32_t kTrbctlControlSetup = trbctl(2);
constexpr uint32_t kTrbctlControlStatus2 = trbctl(3);
constexpr uint32_t kTrbctlControlStatus3 = trbctl(4);
constexpr uint32_t kTrbctlControlData = trbctl(5);

/* Events */
constexpr uint32_t kDepevtXferComplete = 1u;
constexpr uint32_t kDepevtXferNotReady = 3u;
constexpr uint32_t kDepevtStatusControlStatus = 2u;
constexpr uint32_t kDevEventDisconnect = 0u;
constexpr uint32_t kDevEventReset = 1u;
constexpr uint32_t kDevEventConnectDone = 2u;

/* QSCRATCH wrapper (no QUSB2 PHY/GCC/TLMM write is made by this channel). */
constexpr uint32_t kQGeneralCfg = 0x08u;
constexpr uint32_t kQHsPhyCtrl = 0x10u;
constexpr uint32_t kQCgctl = 0x28u;
constexpr uint32_t kQPipeUtmiClkSel = 1u << 0;
constexpr uint32_t kQPipe3PhystatusSw = 1u << 3;
constexpr uint32_t kQUtmiOtgVbusValid = 1u << 20;

/* Physical endpoint numbering includes the direction bit. */
static inline uint32_t
physical_ep(uint32_t number, bool in)
{
	return (number << 1) | (in ? 1u : 0u);
}

/* USB 2.0 CDC-ACM descriptors. */
constexpr uint8_t kDeviceDesc[18] = {
	18, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00, 64,
	0x6b, 0x1d, 0x04, 0x01, 0x00, 0x01,
	1, 2, 3, 1,
};
constexpr uint8_t kConfigDesc[67] = {
	9, 0x02, 67, 0, 2, 1, 0, 0x80, 0x32,
	9, 0x04, 0, 0, 1, 0x02, 0x02, 0x01, 0,
	5, 0x24, 0x00, 0x10, 0x01,
	5, 0x24, 0x01, 0x00, 0x01,
	4, 0x24, 0x02, 0x06,
	5, 0x24, 0x06, 0x00, 0x01,
	7, 0x05, 0x82, 0x03, 16, 0, 16,
	9, 0x04, 1, 0, 2, 0x0a, 0x00, 0x00, 0,
	7, 0x05, 0x81, 0x02, 0, 2, 0,
	7, 0x05, 0x01, 0x02, 0, 2, 0,
};

} // namespace nabu_usb_capture

#endif // NABU_USB_CAPTURE_REGS_H