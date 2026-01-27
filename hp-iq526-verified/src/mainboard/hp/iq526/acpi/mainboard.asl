/* SPDX-License-Identifier: GPL-2.0-only */
/* HP TouchSmart IQ526 mainboard ACPI */

/* Super I/O Hardware Monitor */
Scope (\_SB.PCI0.LPCB)
{
    Device (SIO)
    {
        Name (_HID, EisaId ("PNP0C02"))
        Name (_UID, 0)
        
        /* Hardware Monitor at 0x290 */
        Device (HWM)
        {
            Name (_HID, EisaId ("PNP0C02"))
            Name (_UID, 1)
            
            Name (_CRS, ResourceTemplate ()
            {
                IO (Decode16, 0x0290, 0x0290, 0x01, 0x08)
            })
            
            /* Read CPU temperature (simplified) */
            Method (RTMP, 0, Serialized)
            {
                /* Return temperature in tenths of Kelvin */
                /* Actual implementation reads from HWM registers */
                Return (3132)  /* ~40°C = 313.2K */
            }
        }
    }
}

/* Power button */
Scope (\_SB)
{
    Device (PWRB)
    {
        Name (_HID, EisaId ("PNP0C0C"))
        Name (_PRW, Package () { 0x1D, 0x04 })  /* GPE for wake */
    }
}

/* Include brightness control */
#include "brightness.asl"
