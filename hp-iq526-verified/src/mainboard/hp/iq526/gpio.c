/* SPDX-License-Identifier: GPL-2.0-only */
/* GPIO configuration for HP TouchSmart IQ526 (Maureen / IMIMV-CF)
 *
 * Values captured from vendor BIOS via inteltool -g
 * Northbridge: 8086:2a40 (GM45)
 * Southbridge: 8086:2919 (ICH9M)
 * GPIOBASE = 0x0500
 *
 * EXACT register values from hardware:
 *   GPIO_USE_SEL  (0x00) = 0x1dfe73ce
 *   GP_IO_SEL     (0x04) = 0xe0387fcf
 *   GP_LVL        (0x0c) = 0xeaeeedf5
 *   GPO_BLINK     (0x18) = 0x00000000
 *   GPI_INV       (0x2c) = 0x000071c4
 *   GPIO_USE_SEL2 (0x30) = 0x038300fe
 *   GP_IO_SEL2    (0x34) = 0x0ed5ffb0
 *   GP_LVL2       (0x38) = 0x1f7fffef
 */

#include <southbridge/intel/common/gpio.h>

/*
 * GPIO SET1 (GPIO 0-31) - Derived from 0x1dfe73ce, 0xe0387fcf, 0xeaeeedf5
 *
 * Bit 0x1dfe73ce breakdown:
 *   0: Native (PIRQA#)
 *   1: GPIO
 *   2: GPIO
 *   3: GPIO
 *   4: Native (PIRQB#)  [bit4=0 in 0x...e]
 *   5: Native (PIRQC#)  [bit5=0]
 *   6: GPIO
 *   7: GPIO
 *   8: GPIO
 *   9: GPIO
 *  10: Native (PIRQD#)  [bit10=0 in 0x...7..]
 *  11: Native (SMBALERT#) [bit11=0]
 *  12: GPIO
 *  13: GPIO
 *  14: GPIO  [bit14=1 in 0x..7...]
 *  15: Native [bit15=0]
 *  16: Native [bit16=0]
 *  17: GPIO
 *  18: GPIO
 *  19: GPIO
 *  20: GPIO
 *  21: GPIO
 *  22: GPIO
 *  23: GPIO
 *  24: GPIO
 *  25: Native [bit25=0 in 0x1d..]
 *  26: GPIO
 *  27: GPIO
 *  28: GPIO
 *  29: Native
 *  30: Native
 *  31: Native
 */

static const struct pch_gpio_set1 pch_gpio_set1_mode = {
	.gpio0  = GPIO_MODE_NATIVE,  /* PIRQA# - bit0=0 */
	.gpio1  = GPIO_MODE_GPIO,    /* bit1=1 */
	.gpio2  = GPIO_MODE_GPIO,    /* bit2=1 */
	.gpio3  = GPIO_MODE_GPIO,    /* bit3=1 */
	.gpio4  = GPIO_MODE_NATIVE,  /* PIRQB# - bit4=0 */
	.gpio5  = GPIO_MODE_NATIVE,  /* PIRQC# - bit5=0 */
	.gpio6  = GPIO_MODE_GPIO,    /* bit6=1 */
	.gpio7  = GPIO_MODE_GPIO,    /* bit7=1 */
	.gpio8  = GPIO_MODE_GPIO,    /* bit8=1 */
	.gpio9  = GPIO_MODE_GPIO,    /* bit9=1 */
	.gpio10 = GPIO_MODE_NATIVE,  /* PIRQD# - bit10=0 */
	.gpio11 = GPIO_MODE_NATIVE,  /* SMBALERT# - bit11=0 */
	.gpio12 = GPIO_MODE_GPIO,    /* bit12=1 */
	.gpio13 = GPIO_MODE_GPIO,    /* bit13=1 */
	.gpio14 = GPIO_MODE_GPIO,    /* bit14=1 (NOT native OC7#) */
	.gpio15 = GPIO_MODE_NATIVE,  /* bit15=0 */
	.gpio16 = GPIO_MODE_NATIVE,  /* bit16=0 */
	.gpio17 = GPIO_MODE_GPIO,    /* bit17=1 */
	.gpio18 = GPIO_MODE_GPIO,    /* bit18=1 (NOT native CLKRQ) */
	.gpio19 = GPIO_MODE_GPIO,    /* bit19=1 (NOT native CLKRQ) */
	.gpio20 = GPIO_MODE_GPIO,    /* bit20=1 (NOT native CLKRQ) */
	.gpio21 = GPIO_MODE_GPIO,    /* bit21=1 (NOT native CLKRQ) */
	.gpio22 = GPIO_MODE_GPIO,    /* bit22=1 (NOT native CLKRQ) */
	.gpio23 = GPIO_MODE_GPIO,    /* bit23=1 (NOT native CLKRQ) */
	.gpio24 = GPIO_MODE_GPIO,    /* bit24=1 */
	.gpio25 = GPIO_MODE_NATIVE,  /* bit25=0 */
	.gpio26 = GPIO_MODE_GPIO,    /* bit26=1 */
	.gpio27 = GPIO_MODE_GPIO,    /* bit27=1 */
	.gpio28 = GPIO_MODE_GPIO,    /* bit28=1 */
	.gpio29 = GPIO_MODE_NATIVE,  /* bit29=0 */
	.gpio30 = GPIO_MODE_NATIVE,  /* bit30=0 */
	.gpio31 = GPIO_MODE_NATIVE,  /* bit31=0 */
};

/* GP_IO_SEL = 0xe0387fcf - bit set = input */
static const struct pch_gpio_set1 pch_gpio_set1_direction = {
	.gpio0  = GPIO_DIR_INPUT,    /* Native, don't care */
	.gpio1  = GPIO_DIR_INPUT,    /* bit1=1 */
	.gpio2  = GPIO_DIR_INPUT,    /* bit2=1 */
	.gpio3  = GPIO_DIR_INPUT,    /* bit3=1 */
	.gpio4  = GPIO_DIR_INPUT,    /* Native */
	.gpio5  = GPIO_DIR_INPUT,    /* Native */
	.gpio6  = GPIO_DIR_INPUT,    /* bit6=1 */
	.gpio7  = GPIO_DIR_INPUT,    /* bit7=1 */
	.gpio8  = GPIO_DIR_INPUT,    /* bit8=1 */
	.gpio9  = GPIO_DIR_INPUT,    /* bit9=1 */
	.gpio10 = GPIO_DIR_INPUT,    /* Native */
	.gpio11 = GPIO_DIR_INPUT,    /* Native */
	.gpio12 = GPIO_DIR_INPUT,    /* bit12=1 */
	.gpio13 = GPIO_DIR_INPUT,    /* bit13=1 */
	.gpio14 = GPIO_DIR_INPUT,    /* bit14=1 */
	.gpio15 = GPIO_DIR_INPUT,    /* Native */
	.gpio16 = GPIO_DIR_INPUT,    /* Native */
	.gpio17 = GPIO_DIR_OUTPUT,   /* bit17=0 */
	.gpio18 = GPIO_DIR_OUTPUT,   /* bit18=0 */
	.gpio19 = GPIO_DIR_INPUT,    /* bit19=1 */
	.gpio20 = GPIO_DIR_INPUT,    /* bit20=1 */
	.gpio21 = GPIO_DIR_INPUT,    /* bit21=1 */
	.gpio22 = GPIO_DIR_OUTPUT,   /* bit22=0 */
	.gpio23 = GPIO_DIR_OUTPUT,   /* bit23=0 */
	.gpio24 = GPIO_DIR_OUTPUT,   /* bit24=0 */
	.gpio25 = GPIO_DIR_INPUT,    /* Native */
	.gpio26 = GPIO_DIR_OUTPUT,   /* bit26=0 */
	.gpio27 = GPIO_DIR_OUTPUT,   /* bit27=0 */
	.gpio28 = GPIO_DIR_OUTPUT,   /* bit28=0 */
	.gpio29 = GPIO_DIR_INPUT,    /* Native */
	.gpio30 = GPIO_DIR_INPUT,    /* Native */
	.gpio31 = GPIO_DIR_INPUT,    /* Native */
};

/* GP_LVL = 0xeaeeedf5 - bit set = high */
static const struct pch_gpio_set1 pch_gpio_set1_level = {
	.gpio0  = GPIO_LEVEL_HIGH,   /* bit0=1 */
	.gpio1  = GPIO_LEVEL_LOW,    /* bit1=0 */
	.gpio2  = GPIO_LEVEL_HIGH,   /* bit2=1 */
	.gpio3  = GPIO_LEVEL_LOW,    /* bit3=0 */
	.gpio4  = GPIO_LEVEL_HIGH,   /* bit4=1 */
	.gpio5  = GPIO_LEVEL_HIGH,   /* bit5=1 */
	.gpio6  = GPIO_LEVEL_HIGH,   /* bit6=1 */
	.gpio7  = GPIO_LEVEL_HIGH,   /* bit7=1 */
	.gpio8  = GPIO_LEVEL_HIGH,   /* bit8=1 */
	.gpio9  = GPIO_LEVEL_LOW,    /* bit9=0 */
	.gpio10 = GPIO_LEVEL_HIGH,   /* bit10=1 */
	.gpio11 = GPIO_LEVEL_HIGH,   /* bit11=1 */
	.gpio12 = GPIO_LEVEL_LOW,    /* bit12=0 */
	.gpio13 = GPIO_LEVEL_HIGH,   /* bit13=1 */
	.gpio14 = GPIO_LEVEL_HIGH,   /* bit14=1 */
	.gpio15 = GPIO_LEVEL_HIGH,   /* bit15=1 */
	.gpio16 = GPIO_LEVEL_HIGH,   /* bit16=1 */
	.gpio17 = GPIO_LEVEL_HIGH,   /* bit17=1 */
	.gpio18 = GPIO_LEVEL_HIGH,   /* bit18=1 */
	.gpio19 = GPIO_LEVEL_HIGH,   /* bit19=1 */
	.gpio20 = GPIO_LEVEL_LOW,    /* bit20=0 */
	.gpio21 = GPIO_LEVEL_HIGH,   /* bit21=1 */
	.gpio22 = GPIO_LEVEL_HIGH,   /* bit22=1 */
	.gpio23 = GPIO_LEVEL_HIGH,   /* bit23=1 */
	.gpio24 = GPIO_LEVEL_LOW,    /* bit24=0 */
	.gpio25 = GPIO_LEVEL_HIGH,   /* bit25=1 */
	.gpio26 = GPIO_LEVEL_LOW,    /* bit26=0 */
	.gpio27 = GPIO_LEVEL_HIGH,   /* bit27=1 */
	.gpio28 = GPIO_LEVEL_LOW,    /* bit28=0 */
	.gpio29 = GPIO_LEVEL_HIGH,   /* bit29=1 */
	.gpio30 = GPIO_LEVEL_HIGH,   /* bit30=1 */
	.gpio31 = GPIO_LEVEL_HIGH,   /* bit31=1 */
};

/* GPI_INV = 0x000071c4 - bit set = invert */
static const struct pch_gpio_set1 pch_gpio_set1_invert = {
	.gpio2  = GPIO_INVERT,       /* bit2=1 */
	.gpio6  = GPIO_INVERT,       /* bit6=1 */
	.gpio7  = GPIO_INVERT,       /* bit7=1 */
	.gpio8  = GPIO_INVERT,       /* bit8=1 */
	.gpio12 = GPIO_INVERT,       /* bit12=1 */
	.gpio13 = GPIO_INVERT,       /* bit13=1 */
	.gpio14 = GPIO_INVERT,       /* bit14=1 */
};

/*
 * GPIO SET2 (GPIO 32-63) - Derived from 0x038300fe, 0x0ed5ffb0, 0x1f7fffef
 *
 * GPIO_USE_SEL2 = 0x038300fe breakdown:
 *   32: Native (bit0=0)
 *   33: GPIO (bit1=1)
 *   34: GPIO (bit2=1)
 *   35: GPIO (bit3=1)
 *   36: GPIO (bit4=1)
 *   37: GPIO (bit5=1)
 *   38: GPIO (bit6=1)
 *   39: GPIO (bit7=1)
 *   40-47: Native (bits 8-15 = 0x00)
 *   48: GPIO (bit16=1 in 0x03...)
 *   49: GPIO (bit17=1)
 *   50-54: Native
 *   55: GPIO
 *   56: GPIO
 *   57: GPIO
 *   58-63: Native
 */

static const struct pch_gpio_set2 pch_gpio_set2_mode = {
	.gpio32 = GPIO_MODE_NATIVE,  /* bit0=0 */
	.gpio33 = GPIO_MODE_GPIO,    /* bit1=1 */
	.gpio34 = GPIO_MODE_GPIO,    /* bit2=1 */
	.gpio35 = GPIO_MODE_GPIO,    /* bit3=1 */
	.gpio36 = GPIO_MODE_GPIO,    /* bit4=1 */
	.gpio37 = GPIO_MODE_GPIO,    /* bit5=1 */
	.gpio38 = GPIO_MODE_GPIO,    /* bit6=1 */
	.gpio39 = GPIO_MODE_GPIO,    /* bit7=1 */
	.gpio40 = GPIO_MODE_NATIVE,  /* bit8=0 */
	.gpio41 = GPIO_MODE_NATIVE,  /* bit9=0 */
	.gpio42 = GPIO_MODE_NATIVE,  /* bit10=0 */
	.gpio43 = GPIO_MODE_NATIVE,  /* bit11=0 */
	.gpio44 = GPIO_MODE_NATIVE,  /* bit12=0 */
	.gpio45 = GPIO_MODE_NATIVE,  /* bit13=0 */
	.gpio46 = GPIO_MODE_NATIVE,  /* bit14=0 */
	.gpio47 = GPIO_MODE_NATIVE,  /* bit15=0 */
	.gpio48 = GPIO_MODE_GPIO,    /* bit16=1 */
	.gpio49 = GPIO_MODE_GPIO,    /* bit17=1 */
	.gpio50 = GPIO_MODE_NATIVE,  /* bit18=0 */
	.gpio51 = GPIO_MODE_NATIVE,  /* bit19=0 */
	.gpio52 = GPIO_MODE_NATIVE,  /* bit20=0 */
	.gpio53 = GPIO_MODE_NATIVE,  /* bit21=0 */
	.gpio54 = GPIO_MODE_NATIVE,  /* bit22=0 */
	.gpio55 = GPIO_MODE_GPIO,    /* bit23=1 */
	.gpio56 = GPIO_MODE_GPIO,    /* bit24=1 */
	.gpio57 = GPIO_MODE_GPIO,    /* bit25=1 */
	.gpio58 = GPIO_MODE_NATIVE,  /* bit26=0 */
	.gpio59 = GPIO_MODE_NATIVE,  /* bit27=0 */
	.gpio60 = GPIO_MODE_NATIVE,  /* bit28=0 */
	.gpio61 = GPIO_MODE_NATIVE,  /* bit29=0 */
	.gpio62 = GPIO_MODE_NATIVE,  /* bit30=0 */
	.gpio63 = GPIO_MODE_NATIVE,  /* bit31=0 */
};

/* GP_IO_SEL2 = 0x0ed5ffb0 - bit set = input */
static const struct pch_gpio_set2 pch_gpio_set2_direction = {
	.gpio32 = GPIO_DIR_INPUT,    /* Native */
	.gpio33 = GPIO_DIR_OUTPUT,   /* bit1=0 */
	.gpio34 = GPIO_DIR_OUTPUT,   /* bit2=0 */
	.gpio35 = GPIO_DIR_OUTPUT,   /* bit3=0 */
	.gpio36 = GPIO_DIR_INPUT,    /* bit4=1 */
	.gpio37 = GPIO_DIR_INPUT,    /* bit5=1 */
	.gpio38 = GPIO_DIR_OUTPUT,   /* bit6=0 */
	.gpio39 = GPIO_DIR_INPUT,    /* bit7=1 */
	.gpio40 = GPIO_DIR_INPUT,    /* Native */
	.gpio41 = GPIO_DIR_INPUT,    /* Native */
	.gpio42 = GPIO_DIR_INPUT,    /* Native */
	.gpio43 = GPIO_DIR_INPUT,    /* Native */
	.gpio44 = GPIO_DIR_INPUT,    /* Native */
	.gpio45 = GPIO_DIR_INPUT,    /* Native */
	.gpio46 = GPIO_DIR_INPUT,    /* Native */
	.gpio47 = GPIO_DIR_INPUT,    /* Native */
	.gpio48 = GPIO_DIR_INPUT,    /* bit16=1 */
	.gpio49 = GPIO_DIR_OUTPUT,   /* bit17=0 */
	.gpio50 = GPIO_DIR_INPUT,    /* Native */
	.gpio51 = GPIO_DIR_INPUT,    /* Native */
	.gpio52 = GPIO_DIR_INPUT,    /* Native */
	.gpio53 = GPIO_DIR_INPUT,    /* Native */
	.gpio54 = GPIO_DIR_INPUT,    /* Native */
	.gpio55 = GPIO_DIR_INPUT,    /* bit23=1 */
	.gpio56 = GPIO_DIR_OUTPUT,   /* bit24=0 */
	.gpio57 = GPIO_DIR_INPUT,    /* bit25=1 */
	.gpio58 = GPIO_DIR_INPUT,    /* Native */
	.gpio59 = GPIO_DIR_INPUT,    /* Native */
	.gpio60 = GPIO_DIR_INPUT,    /* Native */
	.gpio61 = GPIO_DIR_INPUT,    /* Native */
	.gpio62 = GPIO_DIR_INPUT,    /* Native */
	.gpio63 = GPIO_DIR_INPUT,    /* Native */
};

/* GP_LVL2 = 0x1f7fffef - bit set = high */
static const struct pch_gpio_set2 pch_gpio_set2_level = {
	.gpio32 = GPIO_LEVEL_HIGH,   /* bit0=1 */
	.gpio33 = GPIO_LEVEL_HIGH,   /* bit1=1 */
	.gpio34 = GPIO_LEVEL_HIGH,   /* bit2=1 */
	.gpio35 = GPIO_LEVEL_HIGH,   /* bit3=1 */
	.gpio36 = GPIO_LEVEL_LOW,    /* bit4=0 */
	.gpio37 = GPIO_LEVEL_HIGH,   /* bit5=1 */
	.gpio38 = GPIO_LEVEL_HIGH,   /* bit6=1 */
	.gpio39 = GPIO_LEVEL_HIGH,   /* bit7=1 */
	.gpio40 = GPIO_LEVEL_HIGH,   /* bit8=1 */
	.gpio41 = GPIO_LEVEL_HIGH,   /* bit9=1 */
	.gpio42 = GPIO_LEVEL_HIGH,   /* bit10=1 */
	.gpio43 = GPIO_LEVEL_HIGH,   /* bit11=1 */
	.gpio44 = GPIO_LEVEL_HIGH,   /* bit12=1 */
	.gpio45 = GPIO_LEVEL_HIGH,   /* bit13=1 */
	.gpio46 = GPIO_LEVEL_HIGH,   /* bit14=1 */
	.gpio47 = GPIO_LEVEL_HIGH,   /* bit15=1 */
	.gpio48 = GPIO_LEVEL_HIGH,   /* bit16=1 */
	.gpio49 = GPIO_LEVEL_HIGH,   /* bit17=1 */
	.gpio50 = GPIO_LEVEL_HIGH,   /* bit18=1 */
	.gpio51 = GPIO_LEVEL_HIGH,   /* bit19=1 */
	.gpio52 = GPIO_LEVEL_HIGH,   /* bit20=1 */
	.gpio53 = GPIO_LEVEL_HIGH,   /* bit21=1 */
	.gpio54 = GPIO_LEVEL_HIGH,   /* bit22=1 */
	.gpio55 = GPIO_LEVEL_LOW,    /* bit23=0 */
	.gpio56 = GPIO_LEVEL_HIGH,   /* bit24=1 */
	.gpio57 = GPIO_LEVEL_HIGH,   /* bit25=1 */
	.gpio58 = GPIO_LEVEL_HIGH,   /* bit26=1 */
	.gpio59 = GPIO_LEVEL_HIGH,   /* bit27=1 */
	.gpio60 = GPIO_LEVEL_HIGH,   /* bit28=1 */
	.gpio61 = GPIO_LEVEL_LOW,    /* bit29=0 - 0x1f = 0001 1111 */
	.gpio62 = GPIO_LEVEL_LOW,    /* bit30=0 */
	.gpio63 = GPIO_LEVEL_LOW,    /* bit31=0 */
};

const struct pch_gpio_map mainboard_gpio_map = {
	.set1 = {
		.mode      = &pch_gpio_set1_mode,
		.direction = &pch_gpio_set1_direction,
		.level     = &pch_gpio_set1_level,
		.invert    = &pch_gpio_set1_invert,
	},
	.set2 = {
		.mode      = &pch_gpio_set2_mode,
		.direction = &pch_gpio_set2_direction,
		.level     = &pch_gpio_set2_level,
	},
};
