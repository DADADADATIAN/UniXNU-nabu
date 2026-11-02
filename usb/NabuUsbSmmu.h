/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * ARM SMMUv2 (MMU-500) stream-matching definitions and bounded plan helpers
 * for the opt-in nabu USB work.  Header-only and MMIO-accessor agnostic so the
 * read-only probe and the CDC driver share one interpretation and the host
 * tests can drive the same code with a fake register function.
 *
 * Layout comes from the ARM SMMUv2 architecture (ARM IHI 0062), as encoded by
 * Linux v6.17 drivers/iommu/arm/arm-smmu/arm-smmu.h:
 *
 *   SMR(n)   @0x800+4n : VALID[31], MASK[30:16], ID[15:0]
 *   S2CR(n)  @0xc00+4n : TYPE[17:16] (0 translate, 1 bypass, 2 fault),
 *                        CBNDX[7:0]
 *   CBAR(n)  @0x1000+4n: TYPE[17:16] (1 = stage-1 translate, stage-2 bypass)
 *   CBA2R(n) @0x1800+4n: VA64[0]
 *   SCTLR    @CB base  : M[0]
 *   IDR0[7:0] = NUMSMRG (number of stream matching groups, not minus one)
 *   IDR0[27]  = SMS, IDR0[8] = EXIDS, IDR0[12:9] = NUMSIDB
 *   IDR1[7:0] = NUMCB, IDR1[23:16] = NUMS2CB, IDR1[30:28] = NUMPAGENDXB,
 *   IDR1[31]  = PAGESIZE (1 = 64 KiB pages; this driver only handles 4 KiB)
 *   IDR2[12]  = PTFS_4K
 *   Context bank n starts at (global_pages + n) * 4096, where global_pages is
 *   2^(NUMPAGENDXB+1) and a 4 KiB page is assumed.
 *
 * The archived NativeDwc3 treated S2CR bits[1:0] as TYPE and wrote the "ARM
 * bypass value 2".  That is not the SMMUv2 layout: bits[1:0] are CBNDX[1:0],
 * bypass is TYPE == 1 at bits[17:16], and 2 is fault.  Its read of S2CR == 3
 * was CBNDX 3 with translation enabled, not a bypass entry.  This header is
 * the authoritative form; nothing here ever writes bits[1:0] of S2CR.
 */
#ifndef NABU_USB_SMMU_H
#define NABU_USB_SMMU_H

#include <stdint.h>

namespace nabu_usb {
namespace smmu {

/* SM8150 apps_smmu, as in the nabu device tree and the qualified NativeUfs
 * planner: GR0/GR1 plus the context-bank window used on hardware. */
constexpr uint64_t kBase = 0x15000000ull;
constexpr uint32_t kWindow = 0x000d0000u;

/* GR0 */
constexpr uint32_t kIdr0 = 0x0020u;
constexpr uint32_t kIdr1 = 0x0024u;
constexpr uint32_t kIdr2 = 0x0028u;
constexpr uint32_t kGfsr = 0x0048u;
constexpr uint32_t kSmrBase = 0x0800u;
constexpr uint32_t kS2crBase = 0x0c00u;

/* GR1 */
constexpr uint32_t kCbarBase = 0x1000u;
constexpr uint32_t kCba2rBase = 0x1800u;

/* Context-bank page (offset 0 inside the bank). */
constexpr uint32_t kSctlr = 0x0000u;

/* IDR0 */
constexpr uint32_t kIdr0NumsmrgMask = 0x000000ffu;
constexpr uint32_t kIdr0Sms = 1u << 27;
constexpr uint32_t kIdr0Exids = 1u << 8;
constexpr uint32_t kIdr0NumsidbShift = 9;
constexpr uint32_t kIdr0NumsidbMask = 0x0000000fu << kIdr0NumsidbShift;

/* IDR1 */
constexpr uint32_t kIdr1Pagesize = 1u << 31;
constexpr uint32_t kIdr1NumpagendxbShift = 28;
constexpr uint32_t kIdr1NumpagendxbMask = 0x00000007u << kIdr1NumpagendxbShift;
constexpr uint32_t kIdr1Nums2cbShift = 16;
constexpr uint32_t kIdr1Nums2cbMask = 0x000000ffu << kIdr1Nums2cbShift;
constexpr uint32_t kIdr1NumcbMask = 0x000000ffu;

/* IDR2 */
constexpr uint32_t kIdr2Ptfs4k = 1u << 12;

/* SMR */
constexpr uint32_t kSmrValid = 1u << 31;
constexpr uint32_t kSmrMaskShift = 16;
constexpr uint32_t kSmrMaskMask = 0x00007fffu << kSmrMaskShift;
constexpr uint32_t kSmrIdMask = 0x0000ffffu;

/* S2CR (authoritative TYPE position). */
constexpr uint32_t kS2crTypeShift = 16;
constexpr uint32_t kS2crTypeMask = 0x00000003u << kS2crTypeShift;
constexpr uint32_t kS2crTypeTrans = 0u;
constexpr uint32_t kS2crTypeBypass = 1u;
constexpr uint32_t kS2crTypeFault = 2u;
constexpr uint32_t kS2crCbndxMask = 0x000000ffu;

/* CBAR / CBA2R / SCTLR. */
constexpr uint32_t kCbarTypeShift = 16;
constexpr uint32_t kCbarTypeMask = 0x00000003u << kCbarTypeShift;
constexpr uint32_t kCbarTypeS2Trans = 0u;
constexpr uint32_t kCbarTypeS1TransS2Bypass = 1u;
constexpr uint32_t kCba2rVa64 = 1u;
constexpr uint32_t kSctlrM = 1u;

/* Sanity bounds.  The SM8150 has 94 groups / 56 banks; a firmware image that
 * reports more than these bounds is treated as unsupported rather than read
 * past the mapped window. */
constexpr uint32_t kMaxSmr = 255;
constexpr uint32_t kMaxBanks = 128;
constexpr uint32_t kMaxGlobalPages = 128;

struct Info {
	uint32_t idr0;
	uint32_t idr1;
	uint32_t idr2;
	uint32_t gfsr;
	uint32_t num_smr;
	uint32_t num_sid_bits;
	uint32_t num_cb;
	uint32_t num_s2_cb;
	uint32_t global_pages;
	bool stream_match;
	bool exids;
	bool page4k;
	bool supported;
};

/* Decode the identification registers.  `read(offset)` returns a 32-bit SMMU
 * register.  Returns false when the geometry cannot be handled without
 * guessing (no stream matching, 64 KiB pages, no 4 KiB stage-2 format, or a
 * register window larger than the mapped space). */
template <typename Read>
bool read_info(Read read, Info *out, uint32_t map_bytes = kWindow)
{
	Info i = {};
	i.idr0 = read(kIdr0);
	i.idr1 = read(kIdr1);
	i.idr2 = read(kIdr2);
	i.gfsr = read(kGfsr);
	i.num_smr = i.idr0 & kIdr0NumsmrgMask;
	i.num_sid_bits = (i.idr0 & kIdr0NumsidbMask) >> kIdr0NumsidbShift;
	i.stream_match = (i.idr0 & kIdr0Sms) != 0;
	i.exids = (i.idr0 & kIdr0Exids) != 0;
	i.page4k = (i.idr1 & kIdr1Pagesize) == 0 && (i.idr2 & kIdr2Ptfs4k) != 0;
	i.num_cb = i.idr1 & kIdr1NumcbMask;
	i.num_s2_cb = (i.idr1 & kIdr1Nums2cbMask) >> kIdr1Nums2cbShift;
	i.global_pages = 1u << (((i.idr1 & kIdr1NumpagendxbMask) >>
	    kIdr1NumpagendxbShift) + 1);
	i.supported = i.stream_match && i.num_smr != 0 && i.num_smr <= kMaxSmr &&
	    i.page4k && i.num_cb >= 2 && i.num_cb <= kMaxBanks &&
	    i.num_s2_cb <= i.num_cb && i.global_pages <= kMaxGlobalPages &&
	    (i.global_pages + i.num_cb) * 4096u <= map_bytes;
	*out = i;
	return i.supported;
}

/* Effective stream-ID width.  Without EXIDS the ID width is 2^NUMSIDB; the
 * field encodes log2(number of stream IDs), matching Linux. */
static inline uint32_t
stream_id_mask(const Info &info)
{
	if (info.exids || info.num_sid_bits >= 16) {
		return 0xffffu;
	}
	return (1u << info.num_sid_bits) - 1u;
}

struct Match {
	uint32_t index;
	uint32_t smr;
	uint32_t s2cr;
	uint32_t id;
	uint32_t mask;
	uint32_t type;
	uint32_t cbndx;
	bool exact;
};

/* Find a unique stream-match entry for `sid`.  Overlapping matches are refused;
 * no priority between overlapping hardware entries is assumed.  Callers must
 * inspect Match::exact before changing a stream.  Matching is mask-aware:
 * ((sid ^ id) & id_width & ~mask) == 0. */
template <typename Read>
bool find_stream(Read read, const Info &info, uint32_t sid, Match *out)
{
	const uint32_t width = stream_id_mask(info);
	const uint32_t want = sid & width;
	if ((sid & ~width) != 0 || info.exids) {
		return false;
	}
	bool found = false;
	for (uint32_t i = 0; i < info.num_smr; ++i) {
		const uint32_t smr = read(kSmrBase + 4u * i);
		if ((smr & kSmrValid) == 0) {
			continue;
		}
		const uint32_t id = smr & kSmrIdMask;
		const uint32_t mask = (smr & kSmrMaskMask) >> kSmrMaskShift;
		if (((want ^ id) & width & ~mask) != 0) {
			continue;
		}
		if (found) {
			return false;
		}
		found = true;
		const uint32_t s2cr = read(kS2crBase + 4u * i);
		out->index = i;
		out->smr = smr;
		out->s2cr = s2cr;
		out->id = id;
		out->mask = mask;
		out->type = (s2cr & kS2crTypeMask) >> kS2crTypeShift;
		out->cbndx = s2cr & kS2crCbndxMask;
		out->exact = mask == 0;
	}
	return found;
}

struct Plan {
	bool valid;
	bool reuse;
	uint32_t index;
	uint32_t bank;
	uint32_t global_pages;
	uint32_t smr;
	uint32_t s2cr;
	uint32_t cbar;
	uint32_t cba2r;
	uint32_t sctlr;
	const char *error;
};

static inline Plan
plan_error(const char *why)
{
	Plan p = {};
	p.error = why;
	return p;
}

static inline uint32_t
context_offset(uint32_t global_pages, uint32_t bank)
{
	return (global_pages + bank) * 4096u;
}

/* True when a stream entry already routes into an identity-bypass context:
 * S2CR.TYPE=translation, SCTLR.M=0 (stage 1 off), CBAR.TYPE=stage-1 translate
 * with stage-2 bypass, CBA2R.VA64=1.  This is exactly the contract the UFS
 * candidate observed on hardware for stream 0x300 (SCTLR=0x009700e0,
 * CBAR=0x0001f000, CBA2R=1): firmware keeps these fields, so the reuse path
 * must not demand they are zero. */
static inline bool
is_bypass_context(uint32_t type, uint32_t sctlr, uint32_t cbar, uint32_t cba2r)
{
	return type == kS2crTypeTrans && (sctlr & kSctlrM) == 0 &&
	    ((cbar & kCbarTypeMask) >> kCbarTypeShift) == kCbarTypeS1TransS2Bypass &&
	    (cba2r & kCba2rVa64) != 0;
}

/* Plan a stream mapping for `sid` that bypasses translation, without writing.
 * - If the SMMU already selects an exact entry for this SID, reuse it only
 *   when its context is the bypass form above; otherwise refuse.  A masked
 *   match means the stream is shared, which is also refused.
 * - Otherwise find the first free SMR group and a free context bank counted
 *   from the top (bank 0 is never used).  A bank is free when no valid SMR
 *   routes a translation to it and its SCTLR/CBAR/CBA2R still read as reset
 *   zeros; refusing otherwise avoids clobbering firmware-owned state.
 * All loops are bounded by the IDR0/IDR1 geometry just decoded. */
template <typename Read>
Plan plan_bypass(Read read, const Info &info, uint32_t sid,
    uint32_t bank_from_top = 0)
{
	if (!info.supported || info.exids || (sid & ~stream_id_mask(info)) != 0) {
		return plan_error("unsupported-smmu-geometry");
	}
	unsigned matches = 0;
	for (uint32_t i = 0; i < info.num_smr; ++i) {
		const uint32_t smr = read(kSmrBase + 4u * i);
		const uint32_t mask = (smr & kSmrMaskMask) >> kSmrMaskShift;
		if ((smr & kSmrValid) &&
		    (((sid ^ smr) & stream_id_mask(info) & ~mask) == 0)) {
			++matches;
		}
	}
	if (matches > 1) {
		return plan_error("ambiguous-stream-match");
	}

	Match match;
	if (find_stream(read, info, sid, &match)) {
		if (!match.exact) {
			return plan_error("masked-stream-match");
		}
		if (match.cbndx == 0 || match.cbndx >= info.num_cb) {
			return plan_error("invalid-context-bank");
		}
		const uint32_t sctlr = read(context_offset(info.global_pages, match.cbndx));
		const uint32_t cbar = read(kCbarBase + 4u * match.cbndx);
		const uint32_t cba2r = read(kCba2rBase + 4u * match.cbndx);
		if (!is_bypass_context(match.type, sctlr, cbar, cba2r)) {
			return plan_error("conflicting-stream-mapping");
		}
		Plan p = {};
		p.valid = true;
		p.reuse = true;
		p.index = match.index;
		p.bank = match.cbndx;
		p.global_pages = info.global_pages;
		p.smr = match.smr;
		p.s2cr = match.s2cr;
		p.cbar = cbar;
		p.cba2r = cba2r;
		p.sctlr = sctlr;
		return p;
	}

	uint32_t slot = info.num_smr;
	for (uint32_t i = 0; i < info.num_smr; ++i) {
		if ((read(kSmrBase + 4u * i) & kSmrValid) == 0) {
			slot = i;
			break;
		}
	}
	if (slot == info.num_smr) {
		return plan_error("no-free-stream-group");
	}

	for (uint32_t attempt = 0; attempt + 1 < info.num_cb; ++attempt) {
		const uint32_t bank = info.num_cb - 1u -
		    ((bank_from_top + attempt) % (info.num_cb - 1u));
		if (bank == 0) {
			continue;
		}
		bool used = false;
		for (uint32_t i = 0; i < info.num_smr && !used; ++i) {
			const uint32_t smr = read(kSmrBase + 4u * i);
			if ((smr & kSmrValid) == 0) {
				continue;
			}
			const uint32_t s2cr = read(kS2crBase + 4u * i);
			const uint32_t type = (s2cr & kS2crTypeMask) >> kS2crTypeShift;
			if (type == kS2crTypeTrans && (s2cr & kS2crCbndxMask) == bank) {
				used = true;
			}
		}
		if (used) {
			continue;
		}
		const uint32_t sctlr = read(context_offset(info.global_pages, bank));
		const uint32_t cbar = read(kCbarBase + 4u * bank);
		const uint32_t cba2r = read(kCba2rBase + 4u * bank);
		if (sctlr != 0 || cbar != 0 || cba2r != 0) {
			continue;
		}
		Plan p = {};
		p.valid = true;
		p.reuse = false;
		p.index = slot;
		p.bank = bank;
		p.global_pages = info.global_pages;
		return p;
	}
	return plan_error("no-free-context-bank");
}

/* Write the plan.  The reuse path performs no writes at all and only verifies
 * that the captured registers did not drift.  The allocation path programs the
 * context bank first, then S2CR, then SMR, and verifies each register.
 * `write(offset, value)` must complete an MMIO barrier before returning. */
template <typename Read, typename Write>
bool configure_bypass(Read read, Write write, const Plan &p, uint32_t sid)
{
	if (!p.valid || p.error != nullptr) {
		return false;
	}
	if (p.reuse) {
		return read(kSmrBase + 4u * p.index) == p.smr &&
		    read(kS2crBase + 4u * p.index) == p.s2cr &&
		    read(context_offset(p.global_pages, p.bank)) == p.sctlr &&
		    read(kCbarBase + 4u * p.bank) == p.cbar &&
		    read(kCba2rBase + 4u * p.bank) == p.cba2r;
	}
	if ((read(kSmrBase + 4u * p.index) & kSmrValid) != 0) {
		return false;
	}
	const uint32_t cb = context_offset(p.global_pages, p.bank);
	write(cb, 0);
	write(kCbarBase + 4u * p.bank, kCbarTypeS1TransS2Bypass << kCbarTypeShift);
	write(kCba2rBase + 4u * p.bank, kCba2rVa64);
	write(kS2crBase + 4u * p.index, p.bank);           /* TYPE=trans, CBNDX=bank */
	write(kSmrBase + 4u * p.index, kSmrValid | (sid & kSmrIdMask));
	return read(cb) == 0 &&
	    read(kCbarBase + 4u * p.bank) ==
	    (kCbarTypeS1TransS2Bypass << kCbarTypeShift) &&
	    read(kCba2rBase + 4u * p.bank) == kCba2rVa64 &&
	    read(kS2crBase + 4u * p.index) == p.bank &&
	    read(kSmrBase + 4u * p.index) == (kSmrValid | (sid & kSmrIdMask));
}

} // namespace smmu
} // namespace nabu_usb

#endif // NABU_USB_SMMU_H