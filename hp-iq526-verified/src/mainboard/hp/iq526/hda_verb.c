/* SPDX-License-Identifier: GPL-2.0-only */

#include <device/azalia_device.h>

const u32 cim_verb_data[] = {
	/* coreboot specific header */
	0x111d76b2,	// Codec Vendor / Device ID: IDT 92HD71B7
	0x103c360b,	// Subsystem ID
	13,		// Number of jacks (NID entries)

	/* NID 0x01, HDA Codec Subsystem ID Verb Table */
	AZALIA_SUBVENDOR(0x0, 0x103c360b),

	/* Pin Complex (NID 0x0A) */
	AZALIA_PIN_CFG(0x0, 0x0a, 0x40f000f0),

	/* Pin Complex (NID 0x0B) */
	AZALIA_PIN_CFG(0x0, 0x0b, 0x0421401f),

	/* Pin Complex (NID 0x0C) */
	AZALIA_PIN_CFG(0x0, 0x0c, 0x04a11020),

	/* Pin Complex (NID 0x0D) */
	AZALIA_PIN_CFG(0x0, 0x0d, 0x90170110),

	/* Pin Complex (NID 0x0E) */
	AZALIA_PIN_CFG(0x0, 0x0e, 0x40f000f0),

	/* Pin Complex (NID 0x0F) */
	AZALIA_PIN_CFG(0x0, 0x0f, 0x40f000f0),

	/* Pin Complex (NID 0x10) */
	AZALIA_PIN_CFG(0x0, 0x10, 0x40f000f0),

	/* Pin Complex (NID 0x11) */
	AZALIA_PIN_CFG(0x0, 0x11, 0x90a60130),

	/* Pin Complex (NID 0x12) */
	AZALIA_PIN_CFG(0x0, 0x12, 0x40f000f0),

	/* Pin Complex (NID 0x13) */
	AZALIA_PIN_CFG(0x0, 0x13, 0x40f000f0),

	/* Pin Complex (NID 0x14) */
	AZALIA_PIN_CFG(0x0, 0x14, 0x40f000f0),

	/* Pin Complex (NID 0x1E) */
	AZALIA_PIN_CFG(0x0, 0x1e, 0x40f000f0),

	/* Pin Complex (NID 0x22) */
	AZALIA_PIN_CFG(0x0, 0x22, 0x40f000f0),
};

const u32 pc_beep_verbs[] = {};

AZALIA_ARRAY_SIZES;
