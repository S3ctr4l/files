/* SPDX-License-Identifier: GPL-2.0-only */

#include <device/device.h>
#include <drivers/intel/gma/int15.h>

static void mainboard_enable(struct device *dev)
{
	/*
	 * Intel GMA INT15 handler for LVDS panel
	 *
	 * Panel: 1680x1050 (WSXGA+) - confirmed via xrandr
	 *
	 * install_intel_vga_int15_handler args:
	 *   active_lfp: 2 = LVDS (internal panel)
	 *   pfit:       0 = no panel fitter scaling
	 *   display:    0 = default display output
	 *   panel_type: 0 = autodetect from VBT/EDID
	 */
	install_intel_vga_int15_handler(GMA_INT15_ACTIVE_LFP_INT_LVDS,
					GMA_INT15_PANEL_FIT_DEFAULT,
					GMA_INT15_BOOT_DISPLAY_DEFAULT, 0);
}

struct chip_operations mainboard_ops = {
	.enable_dev = mainboard_enable,
};
