/* SPDX-License-Identifier: GPL-2.0-only */
/* HD Audio verb table for HP TouchSmart IQ526 (Maureen / IMIMV-CF)
 *
 * Codec: Analog Devices AD1984A
 * Vendor ID: 0x11d4194a
 * Subsystem ID: 0x103c2a82
 * Revision: 0x100400
 *
 * Pin configuration extracted from /proc/asound/card0/codec#0
 */

#include <device/azalia_device.h>

const u32 cim_verb_data[] = {
	/* AD1984A */
	0x11d4194a,	/* Vendor ID */
	0x103c2a82,	/* Subsystem ID */
	12,		/* Number of entries */

	AZALIA_SUBVENDOR(0, 0x103c2a82),

	/*
	 * Pin Widget Verb Table:
	 *
	 * NID 0x11: Headphone Out (Front Jack, Green, 1/8")
	 *           Pin Default: 0x02214040
	 * NID 0x12: Line Out (Rear Jack, Green, 1/8")
	 *           Pin Default: 0x01014010
	 * NID 0x13: Internal Speaker (Rear, Mono, NO_PRESENCE)
	 *           Pin Default: 0x511f11f0
	 * NID 0x14: Line In (Rear Jack, Blue, 1/8") - Disabled
	 *           Pin Default: 0x418130f0
	 * NID 0x15: Line In 2 (Rear Jack, Blue, 1/8") - Disabled
	 *           Pin Default: 0x418130f0
	 * NID 0x16: Internal Speaker (Front, Fixed, NO_PRESENCE)
	 *           Pin Default: 0x9217411f
	 * NID 0x17: Digital Mic In
	 * NID 0x1b: SPDIF Out
	 * NID 0x1c: CD In - Disabled
	 */

	/* NID 0x11: Headphone - Jack, Front, Green */
	AZALIA_PIN_CFG(0, 0x11, 0x02214040),

	/* NID 0x12: Line Out - Jack, Rear, Green */
	AZALIA_PIN_CFG(0, 0x12, 0x01014010),

	/* NID 0x13: Speaker - Internal, Rear, Mono (disabled) */
	AZALIA_PIN_CFG(0, 0x13, 0x511f11f0),

	/* NID 0x14: Line In - Jack, Rear, Blue (disabled) */
	AZALIA_PIN_CFG(0, 0x14, 0x418130f0),

	/* NID 0x15: Line In 2 - Jack, Rear, Blue (disabled) */
	AZALIA_PIN_CFG(0, 0x15, 0x418130f0),

	/* NID 0x16: Speaker - Fixed, Internal Front */
	AZALIA_PIN_CFG(0, 0x16, 0x9217411f),

	/* NID 0x17: Digital Mic - use vendor default */
	AZALIA_PIN_CFG(0, 0x17, AZALIA_PIN_CFG_NC(0)),

	/* NID 0x1b: SPDIF Out */
	AZALIA_PIN_CFG(0, 0x1b, AZALIA_PIN_CFG_NC(0)),

	/* NID 0x1c: CD Audio In (disabled) */
	AZALIA_PIN_CFG(0, 0x1c, AZALIA_PIN_CFG_NC(0)),

	/*
	 * EAPD control - Enable amplifier for internal speaker
	 * NID 0x16 has EAPD capability, enable it
	 */
	0x01670740,	/* Codec GPIO: enable GPIO1 output for amp */
};

const u32 pc_beep_verbs[] = {
	/* Enable PC Beep path through NID 0x10 (Beep Generator) */
	0x01070A00,	/* Unmute beep */
};

AZALIA_ARRAY_SIZES;
