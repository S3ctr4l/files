/* SPDX-License-Identifier: GPL-2.0-only */

#include <southbridge/intel/i82801ix/i82801ix.h>

/*
 * GPIO Configuration for HP TouchSmart IQ526
 * 
 * NOTE: This is a minimal stub configuration.
 * Full GPIO mapping requires extraction from vendor BIOS.
 * 
 * TODO: Extract actual GPIO configuration using:
 *   - UEFITool to analyze vendor BIOS
 *   - inteltool -g on running system with vendor BIOS
 *   - Compare with X200 as baseline
 */

static const struct pch_gpio_set1 pch_gpio_set1_mode = {
	.gpio0  = GPIO_MODE_GPIO,
	.gpio1  = GPIO_MODE_GPIO,
	.gpio2  = GPIO_MODE_GPIO,
	.gpio3  = GPIO_MODE_GPIO,
	.gpio4  = GPIO_MODE_GPIO,
	.gpio5  = GPIO_MODE_GPIO,
	.gpio6  = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio7  = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio8  = GPIO_MODE_GPIO,
	.gpio9  = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio10 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio11 = GPIO_MODE_GPIO,
	.gpio12 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio13 = GPIO_MODE_GPIO,
	.gpio14 = GPIO_MODE_GPIO,
	.gpio15 = GPIO_MODE_GPIO,
	.gpio16 = GPIO_MODE_GPIO,
	.gpio17 = GPIO_MODE_GPIO,
	.gpio18 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio19 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio20 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio21 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio22 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio23 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio24 = GPIO_MODE_GPIO,
	.gpio25 = GPIO_MODE_GPIO,
	.gpio26 = GPIO_MODE_GPIO,
	.gpio27 = GPIO_MODE_GPIO,
	.gpio28 = GPIO_MODE_GPIO,
	.gpio29 = GPIO_MODE_GPIO,
	.gpio30 = GPIO_MODE_NATIVE,  // TODO: Verify
	.gpio31 = GPIO_MODE_NATIVE,  // TODO: Verify
};

static const struct pch_gpio_set1 pch_gpio_set1_direction = {
	.gpio0  = GPIO_DIR_INPUT,
	.gpio1  = GPIO_DIR_OUTPUT,
	.gpio2  = GPIO_DIR_INPUT,
	.gpio3  = GPIO_DIR_INPUT,
	.gpio4  = GPIO_DIR_INPUT,
	.gpio5  = GPIO_DIR_INPUT,
	.gpio8  = GPIO_DIR_OUTPUT,
	.gpio11 = GPIO_DIR_OUTPUT,
	.gpio13 = GPIO_DIR_INPUT,
	.gpio14 = GPIO_DIR_OUTPUT,
	.gpio15 = GPIO_DIR_OUTPUT,
	.gpio16 = GPIO_DIR_OUTPUT,
	.gpio17 = GPIO_DIR_INPUT,
	.gpio24 = GPIO_DIR_OUTPUT,
	.gpio25 = GPIO_DIR_OUTPUT,
	.gpio26 = GPIO_DIR_OUTPUT,
	.gpio27 = GPIO_DIR_OUTPUT,
	.gpio28 = GPIO_DIR_OUTPUT,
	.gpio29 = GPIO_DIR_OUTPUT,
};

static const struct pch_gpio_set1 pch_gpio_set1_level = {
	.gpio1  = GPIO_LEVEL_HIGH,
	.gpio8  = GPIO_LEVEL_HIGH,
	.gpio11 = GPIO_LEVEL_HIGH,
	.gpio14 = GPIO_LEVEL_HIGH,
	.gpio15 = GPIO_LEVEL_LOW,
	.gpio16 = GPIO_LEVEL_LOW,
	.gpio24 = GPIO_LEVEL_LOW,
	.gpio25 = GPIO_LEVEL_HIGH,
	.gpio26 = GPIO_LEVEL_LOW,
	.gpio27 = GPIO_LEVEL_LOW,
	.gpio28 = GPIO_LEVEL_LOW,
	.gpio29 = GPIO_LEVEL_HIGH,
};

static const struct pch_gpio_set1 pch_gpio_set1_invert = {
	.gpio1  = GPIO_INVERT,
	.gpio13 = GPIO_INVERT,
};

static const struct pch_gpio_set1 pch_gpio_set1_blink = {
};

static const struct pch_gpio_set2 pch_gpio_set2_mode = {
	.gpio32 = GPIO_MODE_NATIVE,
	.gpio33 = GPIO_MODE_NATIVE,
	.gpio34 = GPIO_MODE_GPIO,
	.gpio35 = GPIO_MODE_GPIO,
	.gpio36 = GPIO_MODE_GPIO,
	.gpio37 = GPIO_MODE_GPIO,
	.gpio38 = GPIO_MODE_GPIO,
	.gpio39 = GPIO_MODE_GPIO,
};

static const struct pch_gpio_set2 pch_gpio_set2_direction = {
	.gpio34 = GPIO_DIR_OUTPUT,
	.gpio35 = GPIO_DIR_OUTPUT,
	.gpio36 = GPIO_DIR_INPUT,
	.gpio37 = GPIO_DIR_INPUT,
	.gpio38 = GPIO_DIR_OUTPUT,
	.gpio39 = GPIO_DIR_OUTPUT,
};

static const struct pch_gpio_set2 pch_gpio_set2_level = {
	.gpio34 = GPIO_LEVEL_HIGH,
	.gpio35 = GPIO_LEVEL_HIGH,
	.gpio38 = GPIO_LEVEL_LOW,
	.gpio39 = GPIO_LEVEL_HIGH,
};

const struct pch_gpio_map mainboard_gpio_map = {
	.set1 = {
		.mode      = &pch_gpio_set1_mode,
		.direction = &pch_gpio_set1_direction,
		.level     = &pch_gpio_set1_level,
		.blink     = &pch_gpio_set1_blink,
		.invert    = &pch_gpio_set1_invert,
	},
	.set2 = {
		.mode      = &pch_gpio_set2_mode,
		.direction = &pch_gpio_set2_direction,
		.level     = &pch_gpio_set2_level,
	},
};
