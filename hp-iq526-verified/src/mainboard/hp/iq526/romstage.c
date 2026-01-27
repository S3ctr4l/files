/* SPDX-License-Identifier: GPL-2.0-only */
/* Early initialization for HP TouchSmart IQ526 (Maureen / IMIMV-CF) */

#include <stdint.h>
#include <northbridge/intel/gm45/gm45.h>
#include <southbridge/intel/i82801ix/i82801ix.h>

/*
 * Memory configuration from decode-dimms:
 *
 * Single SO-DIMM slot populated:
 *   Slot 0 (0x50): Samsung M470T5663QZ3-CF7, 2GB DDR2-800
 *                  Ranks: 2, CL6-6-6-18
 *
 * This is a single-channel configuration (Channel A only).
 * GM45 supports dual-channel but this board has only one slot.
 */
void mb_get_spd_map(struct spd_info *spdi)
{
	/* Single DIMM on Channel A, slot 0 */
	spdi->addresses[0] = 0x50;  /* Channel A, DIMM 0 */
	spdi->addresses[1] = 0x00;  /* Channel A, DIMM 1 - not present */
	spdi->addresses[2] = 0x00;  /* Channel B, DIMM 0 - not present */
	spdi->addresses[3] = 0x00;  /* Channel B, DIMM 1 - not present */
}

void mb_pre_raminit_setup(sysinfo_t *sysinfo)
{
	/* No special pre-raminit setup required */
	/* EC communication not needed - this is a desktop AIO */
}

void mb_post_raminit_setup(void)
{
	/* RCBA setup if needed */
	/* Most configuration handled by devicetree */
}
