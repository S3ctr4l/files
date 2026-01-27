# SPDX-License-Identifier: GPL-2.0-only

bootblock-y += gpio.c
romstage-y += gpio.c
ramstage-y += gpio.c
ramstage-y += mainboard.c
ramstage-y += hda_verb.c

# ACPI tables
ramstage-$(CONFIG_HAVE_ACPI_TABLES) += acpi/mainboard.asl
