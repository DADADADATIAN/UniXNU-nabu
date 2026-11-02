// SPDX-License-Identifier: BSD-2-Clause-Patent
// Single OS owner after firmware handoff. No secure-world ownership is assumed
// proven by these register checks; the board handoff still requires testing.
#pragma once

static bool hostWaitRegister(unsigned offset, uint32_t mask, uint32_t value)
{
  uint64_t deadline;
  clock_interval_to_deadline(100, kMillisecondScale, &deadline);
  do {
    if ((read32(gHost.hc, offset) & mask) == value) return true;
    IODelay(10);
  } while (mach_absolute_time() < deadline);
  return false;
}

static bool hostQueueFailure(const char **why, const char *reason, IOReturn result)
{
  gHost.poisoned = true;
  gHost.ready = false;
  recordTransport(result, 15);
  *why = reason;
  return false;
}

static bool hostStopQueue(const char **why)
{
  if (gHost.poisoned || gHost.queueOwned)
    return hostQueueFailure(why, "UFS queue ownership unavailable", kIOReturnNotReady);
  if ((read32(gHost.hc, 0x34) & 1) != 1 || (read32(gHost.hc, 0x30) & 15) != 15)
    return hostQueueFailure(why, "controller not ready for takeover", kIOReturnNotReady);
  if (read32(gHost.hc, 0x58) || read32(gHost.hc, 0x78))
    return hostQueueFailure(why, "firmware request outstanding", kIOReturnBusy);
  if (read32(gHost.hc, 0x20) & kUfsFatalStatus)
    return hostQueueFailure(why, "firmware controller error", kIOReturnIOError);

  gHost.queueTouched = true;
  hostWrite(0x24, 0);
  hostWrite(0x60, 0);
  hostWrite(0x80, 0);
  if (!hostWaitRegister(0x60, 1, 0) || !hostWaitRegister(0x80, 1, 0))
    return hostQueueFailure(why, "request/task list stop timeout", kIOReturnTimeout);
  // Recheck after both queues stop, before any SMMU change or new list base.
  if ((read32(gHost.hc, 0x60) & 1) || (read32(gHost.hc, 0x80) & 1) ||
      (read32(gHost.hc, 0x30) & 15) != 15 ||
      read32(gHost.hc, 0x58) || read32(gHost.hc, 0x78) ||
      !(read32(gHost.hc, 0x34) & 1) || (read32(gHost.hc, 0x20) & kUfsFatalStatus))
    return hostQueueFailure(why, "firmware state changed while stopping queues", kIOReturnBusy);
  gHost.queueStopped = true;
  return true;
}

static bool hostStartQueue(const char **why)
{
  if (gHost.poisoned || !gHost.queueStopped || gHost.queueOwned)
    return hostQueueFailure(why, "UFS queue not exclusively stopped", kIOReturnNotReady);
  if ((read32(gHost.hc, 0x60) & 1) || (read32(gHost.hc, 0x80) & 1) ||
      read32(gHost.hc, 0x58) || read32(gHost.hc, 0x78) ||
      (read32(gHost.hc, 0x30) & 15) != 15 ||
      !(read32(gHost.hc, 0x34) & 1) || (read32(gHost.hc, 0x20) & kUfsFatalStatus))
    return hostQueueFailure(why, "firmware state changed before list publication", kIOReturnBusy);

  // Even a failed register readback cannot prove the controller did not see
  // this address. From this point the DMA allocation is never freed/replaced.
  gHost.queueOwned = true;
  hostWrite(0x50, static_cast<uint32_t>(gHost.phys));
  hostWrite(0x54, static_cast<uint32_t>(gHost.phys >> 32));
  if (read32(gHost.hc, 0x50) != uint32_t(gHost.phys) ||
      read32(gHost.hc, 0x54) != uint32_t(gHost.phys >> 32))
    return hostQueueFailure(why, "request list address readback", kIOReturnIOError);
  gRootDiagnostic.isBefore = read32(gHost.hc, 0x20);
  if (gRootDiagnostic.isBefore & kUfsFatalStatus)
    return hostQueueFailure(why, "controller error before queue start", kIOReturnIOError);
  hostWrite(0x20, gRootDiagnostic.isBefore & 1U);
  gHost.queueStopped = false;
  hostWrite(0x60, 1);
  if (!hostWaitRegister(0x60, 1, 1) || !hostWaitRegister(0x30, 3, 3))
    return hostQueueFailure(why, "request list start timeout", kIOReturnTimeout);
  if (read32(gHost.hc, 0x20) & kUfsFatalStatus)
    return hostQueueFailure(why, "controller error after queue start", kIOReturnIOError);
  return true;
}
