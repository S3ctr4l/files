/* SPDX-License-Identifier: GPL-2.0-only */
/* ACPI Brightness control for HP IQ526 LVDS panel */

Scope (\_SB.PCI0.GFX0)
{
    Device (LCD0)
    {
        Name (_ADR, 0x0400)  /* LVDS output */
        
        /* Brightness levels (percentage) */
        Method (_BCL, 0, NotSerialized)
        {
            Return (Package (12)
            {
                100,  /* Full brightness on AC */
                80,   /* Default brightness on battery (N/A for desktop) */
                10, 20, 30, 40, 50, 60, 70, 80, 90, 100
            })
        }
        
        /* Set brightness */
        Method (_BCM, 1, NotSerialized)
        {
            /* Arg0 = brightness percentage (0-100) */
            /* Intel GMA uses BLC_PWM_CTL register */
            /* This is handled by i915 driver in Linux */
            Store (Arg0, BCLP)
        }
        
        /* Query current brightness */
        Method (_BQC, 0, NotSerialized)
        {
            Return (BCLP)
        }
        
        Name (BCLP, 100)  /* Current brightness level */
    }
}
