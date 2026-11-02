// SPDX-License-Identifier: BSD-2-Clause-Patent
// nabu touch: Novatek NT36523 (TDDI) on QUPv3 wrapper 2 SE1 (SE18) SPI,
// published as a touch-only subclass of the original 21H16 IOHIDDevice so the
// unchanged IOHIDInterface -> IOHIDEventDriver -> backboardd path consumes it
// (UniXNU drivers/ShengHidInput design). Protocol and registers follow
// device_bringup/out/nabu-touch-protocol-20261028-01/spec.md; this is new code.
// The proprietary firmware and its partition table come from the private ADT
// node /nabu-touch; nothing runs without the nabu-touch=1 boot argument.
#include "OriginalHidDeviceABI.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSIterator.h>
#include <mach/kmod.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>

extern "C" {
vm_offset_t ml_io_map(vm_offset_t pa, vm_size_t size);
extern kmod_info_t g_kernel_kmod_info;
kern_return_t OSKextLoadKextWithIdentifier(const char *);
void nabu_touch_static_init(void) __asm__("__GLOBAL__sub_I_NabuTouch.cpp");
bool nabu_touch_publish(IOService *platform);
// [0] stage reached, [1] frames read, [2] frames with fingers, [3] checksum drops,
// [4] HID reports sent, [5] last handleReport status, [6] latch hits, [7] firmware downloads
volatile uint32_t nabu_touch_stats[8] = {};
volatile uint64_t nabu_touch_registry_id = 0;
}

#define TLOG(fmt, ...) IOLog("NABU TOUCH " fmt "\n", ##__VA_ARGS__)

namespace {

// ---------------------------------------------------------------- MMIO
struct Mmio {
  volatile uint32_t *base = nullptr;
  uint32_t r(uint32_t off) const { return base[off / 4]; }
  void w(uint32_t off, uint32_t value) const {
    base[off / 4] = value;
    __asm__ volatile("dsb sy" ::: "memory");
  }
};

Mmio map(uint64_t pa, uint32_t size)
{
  Mmio m;
  m.base = reinterpret_cast<volatile uint32_t *>(ml_io_map(static_cast<vm_offset_t>(pa), size));
  return m;
}

uint64_t deadlineUs(uint64_t us)
{
  uint64_t delta;
  nanoseconds_to_absolutetime(us * 1000, &delta);
  return mach_absolute_time() + delta;
}

// ------------------------------------------------- GCC / TLMM / GENI SE18
constexpr uint64_t kGccQupPa = 0x0011e000;   // GCC + 0x1e000: wrap2 AHB CBCRs, S1 CBCR/RCG
constexpr uint64_t kGccVotePa = 0x00152000;  // GCC + 0x52000: APCS clock branch vote at +0x14
constexpr uint64_t kSePa = 0x00c84000;
constexpr uint64_t kTlmmSpiPa = 0x03517000;  // GPIO 23..26, one 0x1000 window each
constexpr uint64_t kTlmmIntPa = 0x03927000;  // GPIO 39
constexpr uint32_t kRcg = 0x278;             // wrap2 S1 RCG CMD within kGccQupPa

enum : uint32_t {
  GENI_FORCE_DEFAULT = 0x20, GENI_OUTPUT_CTRL = 0x24, GENI_CGC_CTRL = 0x28, GENI_STATUS = 0x40,
  GENI_M_CLK_CFG = 0x48, GENI_FIFO_DISABLE = 0x64, GENI_FW_REVISION = 0x68, GENI_CLK_SEL = 0x7c,
  SPI_CPHA = 0x224, SPI_LOOPBACK = 0x22c, SPI_CPOL = 0x230, SPI_DEMUX_INV = 0x24c,
  SPI_DEMUX_SEL = 0x250, GENI_BYTE_GRAN = 0x254, GENI_DMA_MODE = 0x258, SPI_TRANS_CFG = 0x25c,
  TX_PACK0 = 0x260, TX_PACK1 = 0x264, SPI_WORD_LEN = 0x268, SPI_TX_LEN = 0x26c, SPI_RX_LEN = 0x270,
  SPI_PRE_POST_DLY = 0x274, SPI_DELAY = 0x278, RX_PACK0 = 0x284, RX_PACK1 = 0x288,
  M_CMD0 = 0x600, M_CMD_CTRL = 0x604, M_IRQ_STATUS = 0x610, M_IRQ_EN = 0x614, M_IRQ_CLEAR = 0x618,
  S_IRQ_CLEAR = 0x648, TX_FIFO = 0x700, RX_FIFO = 0x780, TX_FIFO_STATUS = 0x800,
  RX_FIFO_STATUS = 0x804, RX_WM = 0x810, RX_RFR_WM = 0x814, GSI_EVENT_EN = 0xe18, SE_IRQ_EN = 0xe1c,
};
constexpr uint32_t kMErrors = 0x3e;          // OVERRUN, ILLEGAL_CMD, FAILURE, CANCEL, ABORT
constexpr uint32_t kFifoWords = 16;

Mmio gSe;
uint8_t *gScratch = nullptr;                 // full-duplex receive buffer
constexpr uint32_t kScratch = 256;

bool clocksUp()
{
  Mmio gcc = map(kGccQupPa, 0x1000), vote = map(kGccVotePa, 0x1000);
  if (!gcc.base || !vote.base) { return false; }
  TLOG("clk before vote=%#x m-ahb=%#x s-ahb=%#x se=%#x rcg=%#x/%#x dfs=%#x", vote.r(0x14),
       gcc.r(0x004), gcc.r(0x008), gcc.r(0x274), gcc.r(kRcg), gcc.r(kRcg + 4), gcc.r(kRcg + 0x14));
  // Shared vote register: only add SE18 core (bit5), wrap2 m-ahb (bit2) and s-ahb (bit1).
  vote.w(0x14, vote.r(0x14) | (1u << 5) | (1u << 2) | (1u << 1));
  uint64_t end = deadlineUs(20000);
  while (((gcc.r(0x004) | gcc.r(0x274)) & 0x80000000u) && mach_absolute_time() < end) { IODelay(10); }
  uint32_t m = gcc.r(0x004), se = gcc.r(0x274);
  TLOG("clk after vote=%#x m-ahb=%#x s-ahb=%#x se=%#x", vote.r(0x14), m, gcc.r(0x008), se);
  if ((m | se) & 0x80000000u) { return false; }
  // Pick an SE clock: DFS levels are preset by firmware and selected by GENI CLK_SEL.
  uint32_t level = 0;
  uint64_t hz = 0;
  if (gcc.r(kRcg + 0x14) & 1) {
    for (uint32_t l = 0; l < 8; l++) {
      uint32_t perf = gcc.r(kRcg + 0x1c + 4 * l);
      uint32_t src = (perf >> 8) & 7, div = perf & 0x1f, mode = (perf >> 12) & 3;
      uint64_t f = src == 0 ? 19200000ull : src == 1 ? 600000000ull : src == 6 ? 300000000ull : 0;
      if (div) { f = f * 2 / (div + 1); }
      if (mode && f) {
        uint32_t mv = gcc.r(kRcg + 0x5c + 4 * l) & 0xffff;
        uint32_t nv = ((~gcc.r(kRcg + 0x9c + 4 * l)) & 0xffff) + mv;
        f = nv ? f * mv / nv : 0;
      }
      TLOG("clk dfs level=%u perf=%#x hz=%llu", l, perf, (unsigned long long)f);
      if (f && (!hz || f < hz)) { hz = f; level = l; }
    }
  } else {
    // No DFS: run the RCG straight from TCXO.
    gcc.w(kRcg + 4, gcc.r(kRcg + 4) & ~0x371fu);
    gcc.w(kRcg, gcc.r(kRcg) | 1);
    end = deadlineUs(2000);
    while ((gcc.r(kRcg) & 1) && mach_absolute_time() < end) { IODelay(1); }
    hz = 19200000ull;
  }
  if (!hz) { hz = 128000000ull; }    // unknown: assume the fastest table entry, stay slow
  uint32_t div = static_cast<uint32_t>((hz + 9600000 - 1) / 9600000);
  if (div < 1) { div = 1; }
  if (div > 0xfff) { div = 0xfff; }
  gSe.w(GENI_CLK_SEL, level);
  gSe.w(GENI_M_CLK_CFG, (div << 4) | 1);
  TLOG("clk se level=%u hz=%llu geni-div=%u sclk=%llu", level, (unsigned long long)hz, div, (unsigned long long)(hz / div));
  return true;
}

void pinsUp()
{
  static const uint32_t ctl[4] = {0x088, 0x08c, 0x08c, 0x088};   // qup18 function, 6 mA, no pull
  Mmio spi = map(kTlmmSpiPa, 0x4000);
  if (spi.base) {
    for (uint32_t i = 0; i < 4; i++) {
      TLOG("pin gpio%u ctl=%#x -> %#x", 23 + i, spi.r(i * 0x1000), ctl[i]);
      spi.w(i * 0x1000, ctl[i]);
    }
  }
}

bool seInit()
{
  uint32_t fw = gSe.r(GENI_FW_REVISION), fifoOff = gSe.r(GENI_FIFO_DISABLE);
  TLOG("se fw=%#x proto=%u fifo-disabled=%u status=%#x m-irq=%#x", fw, (fw >> 8) & 0xff,
       fifoOff & 1, gSe.r(GENI_STATUS), gSe.r(M_IRQ_STATUS));
  if (((fw >> 8) & 0xff) != 1 || (fifoOff & 1)) { return false; }
  if (gSe.r(GENI_STATUS) & 1) {
    gSe.w(M_CMD_CTRL, 1u << 2);
    IODelay(100);
    gSe.w(M_CMD_CTRL, 1u << 1);
    IODelay(100);
  }
  gSe.w(GENI_CGC_CTRL, gSe.r(GENI_CGC_CTRL) | 0x7f);
  gSe.w(GENI_OUTPUT_CTRL, 0x7f);
  gSe.w(GENI_FORCE_DEFAULT, 1);
  gSe.w(GSI_EVENT_EN, 0);
  gSe.w(SE_IRQ_EN, 0);                 // polled: keep the GIC line quiet
  gSe.w(GENI_DMA_MODE, gSe.r(GENI_DMA_MODE) & ~1u);
  gSe.w(M_IRQ_CLEAR, 0xffffffffu);
  gSe.w(S_IRQ_CLEAR, 0xffffffffu);
  gSe.w(M_IRQ_EN, gSe.r(M_IRQ_EN) | 0x4c00003fu);
  gSe.w(RX_WM, 0);
  gSe.w(RX_RFR_WM, kFifoWords - 2);
  gSe.w(TX_PACK0, 0x0007f8fe); gSe.w(TX_PACK1, 0x000ffefe);
  gSe.w(RX_PACK0, 0x0007f8fe); gSe.w(RX_PACK1, 0x000ffefe);
  gSe.w(GENI_BYTE_GRAN, 0);
  gSe.w(SPI_WORD_LEN, 8 - 4);
  gSe.w(SPI_CPHA, 0); gSe.w(SPI_CPOL, 0); gSe.w(SPI_LOOPBACK, 0);
  gSe.w(SPI_DEMUX_SEL, 0); gSe.w(SPI_DEMUX_INV, 0);
  gSe.w(SPI_TRANS_CFG, gSe.r(SPI_TRANS_CFG) & ~1u);
  gSe.w(SPI_PRE_POST_DLY, 0); gSe.w(SPI_DELAY, 0);
  return true;
}

// One CS-asserted transfer: header bytes then payload (payload nullptr sends zeros).
// rx, when given, receives all hlen + plen bytes clocked in.
bool spiXfer(const uint8_t *hdr, uint32_t hlen, const uint8_t *payload, uint32_t plen, uint8_t *rx)
{
  const uint32_t len = hlen + plen;
  uint64_t end = deadlineUs(5000);
  while ((gSe.r(GENI_STATUS) & 1) && mach_absolute_time() < end) { IODelay(1); }
  if (gSe.r(GENI_STATUS) & 1) { return false; }
  gSe.w(M_IRQ_CLEAR, 0xffffffffu);
  gSe.w(SPI_TX_LEN, len);
  if (rx) { gSe.w(SPI_RX_LEN, len); }
  gSe.w(M_CMD0, (rx ? 3u : 1u) << 27);
  uint32_t tx = 0, got = 0;
  end = deadlineUs(50000 + static_cast<uint64_t>(len) * 4);
  for (;;) {
    while (tx < len && (gSe.r(TX_FIFO_STATUS) & 0x0fffffffu) < kFifoWords) {
      uint32_t word = 0;
      for (uint32_t b = 0; b < 4 && tx < len; b++, tx++) {
        uint8_t v = tx < hlen ? hdr[tx] : (payload ? payload[tx - hlen] : 0);
        word |= static_cast<uint32_t>(v) << (8 * b);
      }
      gSe.w(TX_FIFO, word);
    }
    if (rx) {
      uint32_t words = gSe.r(RX_FIFO_STATUS) & 0x1ffffffu;
      while (words--) {
        uint32_t word = gSe.r(RX_FIFO);
        for (uint32_t b = 0; b < 4 && got < len; b++, got++) { rx[got] = static_cast<uint8_t>(word >> (8 * b)); }
      }
    }
    uint32_t irq = gSe.r(M_IRQ_STATUS);
    if (irq & kMErrors) { break; }
    if ((irq & 1) && tx >= len && (!rx || got >= len)) {
      gSe.w(M_IRQ_CLEAR, irq);
      return true;
    }
    if (mach_absolute_time() > end) { break; }
  }
  TLOG("spi fail len=%u tx=%u rx=%u irq=%#x status=%#x", len, tx, got, gSe.r(M_IRQ_STATUS), gSe.r(GENI_STATUS));
  gSe.w(M_CMD_CTRL, 1u << 2);
  IODelay(100);
  if (gSe.r(GENI_STATUS) & 1) { gSe.w(M_CMD_CTRL, 1u << 1); IODelay(100); }
  gSe.w(M_IRQ_CLEAR, 0xffffffffu);
  return false;
}

// ---------------------------------------------------------- NT36523 protocol
bool ntPage(uint32_t addr)
{
  const uint8_t b[3] = {0xff, static_cast<uint8_t>(addr >> 15), static_cast<uint8_t>(addr >> 7)};
  return spiXfer(b, 3, nullptr, 0, nullptr);
}

bool ntWrite(uint32_t addr, const uint8_t *data, uint32_t n)
{
  const uint8_t cmd = static_cast<uint8_t>(0x80 | (addr & 0x7f));
  return spiXfer(&cmd, 1, data, n, nullptr);
}

bool ntRead(uint32_t addr, uint8_t *out, uint32_t n)
{
  if (n + 2 > kScratch) { return false; }
  const uint8_t cmd = static_cast<uint8_t>(addr & 0x7f);
  if (!spiXfer(&cmd, 1, nullptr, n + 1, gScratch)) { return false; }
  memcpy(out, gScratch + 2, n);
  return true;
}

bool ntWriteAddr(uint32_t addr, uint8_t value)
{
  return ntPage(addr) && ntWrite(addr, &value, 1);
}

bool ntReadAddr(uint32_t addr, uint8_t *value)
{
  return ntPage(addr) && ntRead(addr, value, 1);
}

void ntBootloaderReset()
{
  ntWriteAddr(0x3f0fe, 0x69);
  IOSleep(5);
  ntWriteAddr(0x3f310, 0x00);
}

bool ntChipId()
{
  ntWriteAddr(0x7fff80, 0x5a);
  IOSleep(11);
  for (int attempt = 0; attempt < 5; attempt++) {
    ntBootloaderReset();
    uint8_t id[6] = {};
    bool ok = ntPage(0x3f004) && ntRead(0x3f004, id, 6);
    TLOG("chip-id try=%d ok=%d %02x %02x %02x %02x %02x %02x", attempt, ok, id[0], id[1], id[2], id[3], id[4], id[5]);
    if (ok && id[3] == 0x23 && id[4] == 0x65 && id[5] == 0x03) { return true; }
    IOSleep(10);
  }
  return false;
}

struct Firmware {
  const uint8_t *blob = nullptr;
  uint32_t blobSize = 0;
  const uint32_t *parts = nullptr;   // {sram, bin, length-to-write} triples
  uint32_t partCount = 0;
  uint32_t bank[6] = {};             // ILM sram/size/crc, DLM sram/size/crc
};

void ntCrcBank(uint32_t des, uint32_t len, uint32_t gchk, uint32_t sram, uint32_t size, uint32_t crc)
{
  ntPage(des);
  const uint8_t a[3] = {static_cast<uint8_t>(sram), static_cast<uint8_t>(sram >> 8), static_cast<uint8_t>(sram >> 16)};
  ntWrite(des, a, 3);
  const uint8_t l[3] = {static_cast<uint8_t>(size), static_cast<uint8_t>(size >> 8), static_cast<uint8_t>((size >> 16) & 1)};
  ntWrite(len, l, 3);
  const uint8_t c[4] = {static_cast<uint8_t>(crc), static_cast<uint8_t>(crc >> 8), static_cast<uint8_t>(crc >> 16),
                        static_cast<uint8_t>(crc >> 24)};
  ntWrite(gchk, c, 4);
}

uint32_t gXMax = 1600, gYMax = 2560;

bool ntDownload(const Firmware &fw)
{
  for (int attempt = 0; attempt < 3; attempt++) {
    uint64_t start = mach_absolute_time();
    ntBootloaderReset();
    ntCrcBank(0x3f128, 0x3f118, 0x3f100, fw.bank[0], fw.bank[1], fw.bank[2]);
    ntCrcBank(0x3f12c, 0x3f130, 0x3f104, fw.bank[3], fw.bank[4], fw.bank[5]);
    ntWriteAddr(0x3f7e8, 0x69);
    bool sent = true;
    for (uint32_t p = 0; p < fw.partCount && sent; p++) {
      uint32_t sram = fw.parts[3 * p], bin = fw.parts[3 * p + 1], left = fw.parts[3 * p + 2];
      while (left && sent) {
        uint32_t chunk = left < 63 * 1024 ? left : 63 * 1024;
        sent = ntPage(sram) && ntWrite(sram, fw.blob + bin, chunk);
        sram += chunk; bin += chunk; left -= chunk;
      }
    }
    uint8_t dma = 0xee;
    for (int i = 0; i < 200 && sent; i++) {
      if (ntReadAddr(0x3f7f1, &dma) && dma == 0) { break; }
      IOSleep(1);
    }
    uint8_t crcEn = 0;
    ntReadAddr(0x3f30e, &crcEn);
    ntWriteAddr(0x3f30e, crcEn | 0x80);
    ntPage(0x2fe00);
    uint8_t zero = 0, crcCmd = 0xae;
    ntWrite(0x2fe60, &zero, 1);
    ntWrite(0x2fe50, &crcCmd, 1);
    ntWriteAddr(0x3f10d, 1);
    IOSleep(5);
    uint8_t state[5] = {};
    bool booted = false;
    for (int i = 0; i < 10 && !booted; i++) {
      booted = ntPage(0x2fe60) && ntRead(0x2fe60, state, 5) && state[0] >= 0xa0 && state[0] <= 0xaf;
      if (!booted) { IOSleep(10); }
    }
    uint64_t ns;
    absolutetime_to_nanoseconds(mach_absolute_time() - start, &ns);
    TLOG("fw download try=%d sent=%d dma=%#x reset-state=%#x booted=%d ms=%llu", attempt, sent, dma,
         state[0], booted, (unsigned long long)(ns / 1000000));
    if (!booted) {
      uint8_t crcFlags = 0;
      ntReadAddr(0x3f133, &crcFlags);
      TLOG("fw crc flags=%#x", crcFlags);
      continue;
    }
    uint8_t info[38] = {};
    if (ntPage(0x2fe78) && ntRead(0x2fe78, info, sizeof(info))) {
      uint32_t xm = (info[4] << 8) | info[5], ym = (info[6] << 8) | info[7];
      TLOG("fw info ver=%#x/%#x xnum=%u ynum=%u xmax=%u ymax=%u type=%#x", info[0], info[1], info[2], info[3], xm,
           ym, info[13]);
      if (static_cast<uint8_t>(info[0] + info[1]) == 0xff && xm && ym) { gXMax = xm; gYMax = ym; }
    }
    uint8_t pid[2] = {};
    if (ntPage(0x2fe9a) && ntRead(0x2fe9a, pid, 2)) { TLOG("fw pid=%#x", pid[0] | (pid[1] << 8)); }
    ntPage(0x2fe00);
    nabu_touch_stats[7] = nabu_touch_stats[7] + 1;
    return true;
  }
  return false;
}

// ------------------------------------------------------------ edge contacts
// SpringBoard's screen-edge recognizers need kIOHIDDigitizerEventFromEdgeTip on
// contacts that begin at a panel edge; the original IOHIDEventDriver never sets
// it. As in UniXNU ShengHidInput, this device's own event driver gets a copy of
// its vtable whose dispatchEvent (slot 198) adds the bit (IOHIDFamily-2031.120.4
// layouts: IOHIDEvent getType 18, getIntegerValue 23, setIntegerValue 24,
// getFixedValue 25, _children at +24).
namespace edge {
enum { kSlots = 256, kDispatch = 198, kGetType = 18, kGetInteger = 23, kSetInteger = 24, kGetFixed = 25, kContacts = 256 };
enum : uint32_t { kDigitizer = 11, kX = 0xB0000, kY = 0xB0001, kIndex = 0xB0005, kMask = 0xB0007, kTouch = 0xB0009,
                  kMaskTouch = 2, kFromEdgeTip = 0x800 };
// 48 panel pixels of the 1600 x 2560 portrait panel, in normalised IOFixed.
const int32_t kEdgeX = 48 * 65536 / 1600, kEdgeY = 48 * 65536 / 2560;
uintptr_t originalDispatch;
bool fromEdge[kContacts];

template <typename R, typename... A> R call(void *object, unsigned slot, A... args)
{
  return reinterpret_cast<R (*)(void *, A...)>((*reinterpret_cast<uintptr_t **>(object))[slot])(object, args...);
}

bool mark(void *child)
{
  if (call<uint32_t, IOOptionBits>(child, kGetType, 0) != kDigitizer) { return false; }
  const uint32_t index = static_cast<uint32_t>(call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kIndex, 0));
  if (index >= kContacts) { return false; }
  const uint32_t mask = static_cast<uint32_t>(call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kMask, 0));
  const bool touch = call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kTouch, 0) != 0;
  if ((mask & kMaskTouch) && touch) {
    const int32_t x = call<int32_t, uint32_t, IOOptionBits>(child, kGetFixed, kX, 0);
    const int32_t y = call<int32_t, uint32_t, IOOptionBits>(child, kGetFixed, kY, 0);
    fromEdge[index] = x < kEdgeX || x > 65536 - kEdgeX || y < kEdgeY || y > 65536 - kEdgeY;
  }
  const bool edged = fromEdge[index];
  if (edged) { call<void, uint32_t, int32_t, IOOptionBits>(child, kSetInteger, kMask, static_cast<int32_t>(mask | kFromEdgeTip), 0); }
  if (!touch && (mask & kMaskTouch)) { fromEdge[index] = false; }
  return edged;
}

void dispatch(IOService *self, OSObject *event, IOOptionBits options)
{
  if (event && call<uint32_t, IOOptionBits>(event, kGetType, 0) == kDigitizer) {
    OSArray *children = *reinterpret_cast<OSArray **>(reinterpret_cast<uint8_t *>(event) + 24);
    if (children && OSDynamicCast(OSArray, children) && children->getCount()) {
      bool any = false;
      for (unsigned i = 0; i < children->getCount(); ++i) {
        OSObject *child = children->getObject(i);
        if (child && child->metaCast("IOHIDEvent")) { any |= mark(child); }
      }
      if (any) {
        const uint32_t mask = static_cast<uint32_t>(call<int32_t, uint32_t, IOOptionBits>(event, kGetInteger, kMask, 0));
        call<void, uint32_t, int32_t, IOOptionBits>(event, kSetInteger, kMask, static_cast<int32_t>(mask | kFromEdgeTip), 0);
      }
    } else if (!children) {
      mark(event);
    }
  }
  reinterpret_cast<void (*)(IOService *, OSObject *, IOOptionBits)>(originalDispatch)(self, event, options);
}

void install(IORegistryEntry *driver)
{
  if (originalDispatch || !driver) { return; }
  uintptr_t *table = *reinterpret_cast<uintptr_t **>(driver);
  uintptr_t *copy = static_cast<uintptr_t *>(IOMalloc(kSlots * sizeof(uintptr_t)));
  if (!copy) { return; }
  memcpy(copy, table, kSlots * sizeof(uintptr_t));
  originalDispatch = copy[kDispatch];
  copy[kDispatch] = reinterpret_cast<uintptr_t>(&dispatch);
  __asm__ volatile("dmb ish" ::: "memory");
  *reinterpret_cast<uintptr_t **>(driver) = copy;
  TLOG("edge dispatch wrapper installed");
}
}  // namespace edge

constexpr unsigned kFingers = 10;
struct Frame {
  unsigned count;
  int ids[kFingers], xs[kFingers], ys[kFingers];   // normalised 0..32767
};

}  // namespace

// --------------------------------------------------------- HID digitizer
// Report 1: ten fingers (Tip Switch, Touch Valid, Contact Identifier, X, Y), then Contact Count.
#define FINGER_DESC \
  0x09,0x22,0xa1,0x02, 0x09,0x42,0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x01,0x81,0x02, 0x09,0x47,0x81,0x02, \
  0x75,0x06,0x95,0x01,0x81,0x03, 0x09,0x51,0x75,0x08,0x95,0x01,0x15,0x00,0x26,0xff,0x00,0x81,0x02, \
  0x05,0x01,0x09,0x30,0x15,0x00,0x26,0xff,0x7f,0x75,0x10,0x95,0x01,0x81,0x02, 0x09,0x31,0x81,0x02, 0x05,0x0d, 0xc0,
static const unsigned char kTouchDescriptor[] = {
  0x05,0x0d,0x09,0x04,0xa1,0x01,0x85,0x01,
  FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC
  FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC
  0x09,0x54,0x75,0x08,0x95,0x01,0x15,0x00,0x26,0xff,0x00,0x81,0x02,0xc0
};

class NabuTouchHid : public IOHIDDevice {
  OSDeclareDefaultStructors(NabuTouchHid)
  IOWorkLoop *inputLoop = nullptr;
  bool eventDriverFound = false;
  bool edgeEnabled = true;
  int prevIds[kFingers] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
  int prevX[kFingers] = {}, prevY[kFingers] = {};

  static IORegistryEntry *eventDriver(IORegistryEntry *parent, unsigned depth)
  {
    if (!depth) { return nullptr; }
    OSIterator *it = parent->getChildIterator(gIOServicePlane);
    if (!it) { return nullptr; }
    IORegistryEntry *found = nullptr;
    while (OSObject *child = it->getNextObject()) {
      IORegistryEntry *entry = OSDynamicCast(IORegistryEntry, child);
      if (!entry) { continue; }
      found = entry->metaCast("IOHIDEventDriver") ? entry : eventDriver(entry, depth - 1);
      if (found) { break; }
    }
    it->release();
    return found;
  }

  bool hasEventDriver()
  {
    if (!eventDriverFound) {
      IORegistryEntry *driver = eventDriver(this, 4);
      eventDriverFound = driver != nullptr;
      if (driver) {
        TLOG("IOHIDEventDriver attached registry-id=%llu", (unsigned long long)driver->getRegistryEntryID());
        if (edgeEnabled) { edge::install(driver); }
      }
    }
    return eventDriverFound;
  }

  static IOReturn sendAction(OSObject *owner, void *arg, void *, void *, void *)
  {
    NabuTouchHid *self = OSDynamicCast(NabuTouchHid, owner);
    if (self) { self->send(*static_cast<const Frame *>(arg)); }
    return kIOReturnSuccess;
  }

  void send(const Frame &frame)
  {
    if (!hasEventDriver()) { return; }
    unsigned char report[1 + kFingers * 6 + 1] = {1};
    unsigned slot = 0;
    for (unsigned i = 0; i < frame.count && slot < kFingers; ++i, ++slot) {
      unsigned char *f = report + 1 + slot * 6;
      f[0] = 3;   // tip, valid
      f[1] = static_cast<unsigned char>(frame.ids[i]);
      f[2] = static_cast<unsigned char>(frame.xs[i]); f[3] = static_cast<unsigned char>(frame.xs[i] >> 8);
      f[4] = static_cast<unsigned char>(frame.ys[i]); f[5] = static_cast<unsigned char>(frame.ys[i] >> 8);
    }
    const unsigned down = slot;
    // Identifiers that were down and are gone: one tip-up entry at the last position.
    for (unsigned j = 0; j < kFingers; ++j) {
      const int id = prevIds[j];
      if (id < 0) { continue; }
      bool kept = false;
      for (unsigned i = 0; i < down && !kept; ++i) { kept = frame.ids[i] == id; }
      if (kept || slot >= kFingers) { continue; }
      unsigned char *f = report + 1 + slot * 6;
      f[0] = 2;   // tip up, valid
      f[1] = static_cast<unsigned char>(id);
      f[2] = static_cast<unsigned char>(prevX[j]); f[3] = static_cast<unsigned char>(prevX[j] >> 8);
      f[4] = static_cast<unsigned char>(prevY[j]); f[5] = static_cast<unsigned char>(prevY[j] >> 8);
      ++slot;
    }
    for (unsigned j = 0; j < kFingers; ++j) {
      prevIds[j] = j < down ? frame.ids[j] : -1;
      if (j < down) { prevX[j] = frame.xs[j]; prevY[j] = frame.ys[j]; }
    }
    if (!slot) { return; }
    report[1 + kFingers * 6] = static_cast<unsigned char>(slot);
    IOBufferMemoryDescriptor *buffer = IOBufferMemoryDescriptor::withBytes(report, sizeof(report), kIODirectionNone);
    IOReturn result = buffer ? handleReport(buffer, 0, 0) : kIOReturnNoMemory;
    OSSafeReleaseNULL(buffer);
    nabu_touch_stats[4] = nabu_touch_stats[4] + 1;
    nabu_touch_stats[5] = static_cast<uint32_t>(result);
  }

public:
  void deliver(const Frame &frame)
  {
    if (inputLoop) { inputLoop->runAction(&NabuTouchHid::sendAction, this, const_cast<Frame *>(&frame)); }
  }
  IOWorkLoop *getWorkLoop() const override { return inputLoop; }
  OSString *newTransportString() const override { return OSString::withCString("SPI"); }
  OSString *newProductString() const override { return OSString::withCString("nabu NT36523 touch"); }
  IOReturn newReportDescriptor(IOMemoryDescriptor **out) const override
  {
    if (!out) { return kIOReturnBadArgument; }
    *out = IOBufferMemoryDescriptor::withBytes(kTouchDescriptor, sizeof(kTouchDescriptor), kIODirectionNone);
    return *out ? kIOReturnSuccess : kIOReturnNoMemory;
  }
  bool start(IOService *provider) override
  {
    inputLoop = IOWorkLoop::workLoop();
    if (!inputLoop) { return false; }
    uint32_t value = 1;
    if (PE_parse_boot_argn("nabu-touch-edge", &value, sizeof(value))) { edgeEnabled = value != 0; }
    // Matching and routing contract of the original generic event driver and backboardd:
    // generic personality, built-in main-display digitizer, one collection per report,
    // no edge band removed, and no displayUUID.
    setProperty("HIDDefaultBehavior", true);
    setProperty("Built-In", true);
    setProperty("DisplayIntegrated", true);
    setProperty("DigitizerCollectionDispatch", true);
    setProperty("AbsoluteAxisBoundsRemovalPercentage", 0ull, 32);
    return IOHIDDevice::start(provider);
  }
  void stop(IOService *provider) override { IOHIDDevice::stop(provider); }
  void free() override
  {
    OSSafeReleaseNULL(inputLoop);
    IOHIDDevice::free();
  }
};

OSDefineMetaClassAndStructors(NabuTouchHid, IOHIDDevice)
static_assert(sizeof(NabuTouchHid) > 0xd0, "Original device storage precedes the owned fields");

namespace {

IOService *gPlatform = nullptr;
uint32_t gSwapXY = 0, gInvertX = 0, gInvertY = 0;

NabuTouchHid *publishHid()
{
  kern_return_t result = OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
  TLOG("IOHIDFamily load=%d", result);
  if (result != KERN_SUCCESS) { return nullptr; }
  // The original IOHIDDevice metaclass must exist before the subclass initializer runs.
  void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
  if (!handle) { return nullptr; }
  nabu_touch_static_init();
  if (OSMetaClass::postModLoad(handle) != KERN_SUCCESS) {
    TLOG("subclass registration failed");
    return nullptr;
  }
  NabuTouchHid *device = new NabuTouchHid;
  if (!device) { return nullptr; }
  if (!device->init(nullptr) || !device->attach(gPlatform)) {
    device->release();
    return nullptr;
  }
  if (!device->start(gPlatform)) {
    device->detach(gPlatform);
    device->release();
    TLOG("original IOHIDDevice start failed");
    return nullptr;
  }
  nabu_touch_registry_id = device->getRegistryEntryID();
  TLOG("HID digitizer published registry-id=%llu", (unsigned long long)nabu_touch_registry_id);
  return device;
}

bool loadFirmware(Firmware &fw)
{
  IORegistryEntry *node = IORegistryEntry::fromPath("/nabu-touch", gIODTPlane);
  if (!node) { TLOG("ADT /nabu-touch missing"); return false; }
  OSData *blob = OSDynamicCast(OSData, node->getProperty("firmware"));
  OSData *parts = OSDynamicCast(OSData, node->getProperty("partitions"));
  OSData *bank = OSDynamicCast(OSData, node->getProperty("crc-bank"));
  bool ok = blob && parts && bank && parts->getLength() && parts->getLength() % 12 == 0 && bank->getLength() == 24;
  if (ok) {
    fw.blob = static_cast<const uint8_t *>(blob->getBytesNoCopy());
    fw.blobSize = blob->getLength();
    fw.parts = static_cast<const uint32_t *>(parts->getBytesNoCopy());
    fw.partCount = parts->getLength() / 12;
    memcpy(fw.bank, bank->getBytesNoCopy(), 24);
    for (uint32_t p = 0; p < fw.partCount && ok; p++) {
      ok = fw.parts[3 * p + 1] <= fw.blobSize && fw.parts[3 * p + 2] <= fw.blobSize - fw.parts[3 * p + 1];
    }
    const struct { const char *key; uint32_t *value; } flags[] = {
      {"swap-xy", &gSwapXY}, {"invert-x", &gInvertX}, {"invert-y", &gInvertY}};
    for (const auto &flag : flags) {
      OSData *d = OSDynamicCast(OSData, node->getProperty(flag.key));
      if (d && d->getLength() == 4) { *flag.value = *static_cast<const uint32_t *>(d->getBytesNoCopy()); }
    }
  }
  TLOG("firmware ok=%d bytes=%u partitions=%u swap=%u invx=%u invy=%u", ok, fw.blobSize, fw.partCount, gSwapXY,
       gInvertX, gInvertY);
  node->release();
  return ok;
}

int scale(int value, int maximum, bool invert)
{
  if (value < 0) { value = 0; }
  if (value > maximum) { value = maximum; }
  if (invert) { value = maximum - value; }
  return static_cast<int>(static_cast<long long>(value) * 32767 / maximum);
}

// Decode one 80-byte event page; false means skip this read.
bool decode(const uint8_t *d, Frame &frame, bool &wdtPattern, unsigned logBudget)
{
  wdtPattern = true;
  bool esd = true;
  for (int i = 0; i < 6; i++) {
    esd &= d[i] == 0x77;
    wdtPattern &= d[i] == 0xfd || d[i] == 0xfe;
  }
  if (esd || wdtPattern) { return false; }
  uint8_t sum = 0;
  for (int i = 0; i < 64; i++) { sum = static_cast<uint8_t>(sum + d[i]); }
  if (static_cast<uint8_t>(-sum) != d[64]) {
    nabu_touch_stats[3] = nabu_touch_stats[3] + 1;
    return false;
  }
  frame.count = 0;
  for (unsigned i = 0; i < kFingers; i++) {
    const uint8_t *p = d + 6 * i;
    int id = p[0] >> 3, st = p[0] & 7;
    if (id < 1 || id > static_cast<int>(kFingers) || (st != 1 && st != 2)) { continue; }
    int x = (p[1] << 4) | (p[3] >> 4), y = (p[2] << 4) | (p[3] & 0x0f);
    if (x > static_cast<int>(gXMax) || y > static_cast<int>(gYMax)) { continue; }
    if (logBudget) { TLOG("finger id=%d st=%d x=%d y=%d w=%u p=%u", id, st, x, y, p[4], p[5]); }
    int sx = gSwapXY ? y : x, sy = gSwapXY ? x : y;
    int mx = static_cast<int>(gSwapXY ? gYMax : gXMax), my = static_cast<int>(gSwapXY ? gXMax : gYMax);
    frame.ids[frame.count] = id;
    frame.xs[frame.count] = scale(sx, mx, gInvertX);
    frame.ys[frame.count] = scale(sy, my, gInvertY);
    frame.count++;
  }
  return true;
}

void touchThread(void *, wait_result_t)
{
  uint32_t delay = 10;
  PE_parse_boot_argn("nabu-touch-delay", &delay, sizeof(delay));
  IOSleep(delay * 1000);
  nabu_touch_stats[0] = 1;
  NabuTouchHid *hid = publishHid();
  Firmware fw;
  gScratch = static_cast<uint8_t *>(IOMalloc(kScratch));
  if (!hid || !gScratch || !loadFirmware(fw)) { TLOG("stopped before hardware"); return; }
  nabu_touch_stats[0] = 2;
  gSe = map(kSePa, 0x4000);
  if (!gSe.base || !clocksUp()) { TLOG("clocks not available; stopped"); return; }
  nabu_touch_stats[0] = 3;
  pinsUp();
  if (!seInit()) { TLOG("SE18 not usable as FIFO SPI; stopped"); return; }
  nabu_touch_stats[0] = 4;
  if (!ntChipId()) { TLOG("NT36523 not identified; stopped"); return; }
  nabu_touch_stats[0] = 5;
  if (!ntDownload(fw)) { TLOG("firmware download failed; stopped"); return; }
  nabu_touch_stats[0] = 6;
  Mmio irq = map(kTlmmIntPa, 0x1000);
  if (irq.base) {
    TLOG("gpio39 ctl=%#x io=%#x cfg=%#x st=%#x", irq.r(0), irq.r(4), irq.r(8), irq.r(0xc));
    irq.w(0, 0x1c1);      // input, pull-down, 16 mA
    irq.w(8, 0x16);       // rising edge latched in RAW_STATUS, no CPU interrupt
    irq.w(0xc, 0);
  }
  TLOG("polling started xmax=%u ymax=%u", gXMax, gYMax);
  uint8_t event[80];
  uint8_t last[80] = {};
  bool latchSeen = false;
  unsigned wdtRun = 0, logBudget = 24, lastFingers = 0;
  uint64_t nextStatus = deadlineUs(30000000);
  for (;;) {
    bool latched = irq.base && (irq.r(0xc) & 1);
    if (latched) {
      irq.w(0xc, 0);
      latchSeen = true;
      nabu_touch_stats[6] = nabu_touch_stats[6] + 1;
    }
    if (latched || !latchSeen) {
      if (ntRead(0x2fe00, event, sizeof(event))) {
        nabu_touch_stats[1] = nabu_touch_stats[1] + 1;
        Frame frame;
        bool wdtPattern = false;
        bool changed = latched || memcmp(event, last, sizeof(event)) != 0;
        if (changed && decode(event, frame, wdtPattern, logBudget)) {
          wdtRun = 0;
          memcpy(last, event, sizeof(event));
          if (frame.count) {
            nabu_touch_stats[2] = nabu_touch_stats[2] + 1;
            if (logBudget) { logBudget--; }
          }
          if (frame.count || lastFingers) { hid->deliver(frame); }
          lastFingers = frame.count;
        } else if (wdtPattern && ++wdtRun > 10) {
          TLOG("firmware reset pattern; downloading again");
          wdtRun = 0;
          if (!ntDownload(fw)) { TLOG("re-download failed; stopped"); return; }
        }
      }
    }
    if (mach_absolute_time() > nextStatus) {
      TLOG("status reads=%u fingers=%u bad-sum=%u reports=%u last=%#x latch=%u", nabu_touch_stats[1],
           nabu_touch_stats[2], nabu_touch_stats[3], nabu_touch_stats[4], nabu_touch_stats[5], nabu_touch_stats[6]);
      nextStatus = deadlineUs(60000000);
    }
    IOSleep(8);
  }
}

}  // namespace

extern "C" bool nabu_touch_publish(IOService *platform)
{
  uint32_t enabled = 0;
  if (!PE_parse_boot_argn("nabu-touch", &enabled, sizeof(enabled)) || enabled != 1) { return false; }
  platform->retain();
  gPlatform = platform;
  thread_t thread;
  if (kernel_thread_start(touchThread, nullptr, &thread) != KERN_SUCCESS) {
    TLOG("worker thread start failed");
    return false;
  }
  thread_deallocate(thread);
  TLOG("worker started");
  return true;
}
