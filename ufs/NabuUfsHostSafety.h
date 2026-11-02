// SPDX-License-Identifier: BSD-2-Clause-Patent
// Included after the host state; also compiled by the portable lifecycle test.
#pragma once

static bool hostBeginBringup(const char **why)
{
  // One attempt per kernel lifetime. A later request cannot replace buffers
  // whose ownership may have become ambiguous during the first attempt.
  if (__atomic_exchange_n(&gHost.attempted, true, __ATOMIC_ACQ_REL)) {
    *why = "UFS bring-up already attempted";
    return false;
  }
  if (gHost.poisoned || gHost.dma || gHost.lock || gHost.queueOwned) {
    gHost.poisoned = true;
    *why = "unexpected existing UFS host state";
    return false;
  }
  return true;
}

static bool hostDmaRangeValid(uint64_t physical, uint64_t contiguous, bool address64)
{
  if (!physical || (physical & 4095) || contiguous < kDmaBytes ||
      physical > UINT64_MAX - kDmaBytes) return false;
  return address64 || (physical < 0x100000000ULL &&
                       kDmaBytes <= 0x100000000ULL - physical);
}

struct HostPreparedDmaGuard {
  bool keep = false;
  HostPreparedDmaGuard() = default;
  HostPreparedDmaGuard(const HostPreparedDmaGuard &) = delete;
  HostPreparedDmaGuard &operator=(const HostPreparedDmaGuard &) = delete;
  ~HostPreparedDmaGuard()
  {
    // Before publishing our list base, hardware has never been given this
    // allocation. After publication (including failed readback/start), retain
    // it for the rest of the kernel lifetime. No guessed reset or cancellation.
    if (keep || gHost.queueOwned) return;
    if (gHost.dma) { gHost.dma->release(); gHost.dma = nullptr; }
    if (gHost.lock) { IOLockFree(gHost.lock); gHost.lock = nullptr; }
    gHost.virt = nullptr;
    gHost.phys = 0;
  }
};
