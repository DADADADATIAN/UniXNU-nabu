// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "NabuBoard.h"

struct NabuUfsResources {
  uint64_t hc[2], gcc[2], smmu[2];
  uint32_t stream, blockBytes;
};

static bool nabuUfsResourcesMatch(const NabuUfsResources &r)
{
  const auto &b = nabu_ufs::kBoard;
  return r.hc[0] == b.hcBase && r.hc[1] == b.hcBytes &&
         r.gcc[0] == b.gccBase + 0x77000 && r.gcc[1] == 0x1000 &&
         r.smmu[0] == b.smmuBase && r.smmu[1] == b.smmuBytes &&
         r.stream == b.streamId && r.blockBytes == b.logicalBlockBytes;
}

static bool nabuUfsClocksReady(uint32_t gdsc, uint32_t axi, uint32_t ahb)
{
  return gdsc != UINT32_MAX && axi != UINT32_MAX && ahb != UINT32_MAX &&
         (gdsc & 0x80000000U) && !(axi & 0x80000000U) && !(ahb & 0x80000000U);
}

static bool nabuUfsRequestGeometry(bool physical, uint64_t bytes, uint64_t block,
                                  uint64_t count, uint64_t bufferBytes,
                                  uint64_t &windowBlock, uint64_t &windowCount)
{
  const uint64_t sector = physical ? 4096 : 512;
  if (!count || block >= bytes / sector || count > bytes / sector - block ||
      bufferBytes < count * sector) return false;
  windowBlock = block * (sector / 512);
  windowCount = count * (sector / 512);
  return true;
}
