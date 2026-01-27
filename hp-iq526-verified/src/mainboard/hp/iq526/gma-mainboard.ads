-- SPDX-License-Identifier: GPL-2.0-only
--
-- libgfxinit port configuration for HP TouchSmart IQ526
-- Panel: 1680x1050 LVDS (dual-channel)

with HW.GFX.GMA;
with HW.GFX.GMA.Display_Probing;

use HW.GFX.GMA;
use HW.GFX.GMA.Display_Probing;

private package GMA.Mainboard is

   ports : constant Port_List :=
     (LVDS,        -- Internal 1680x1050 panel
      HDMI1,       -- External HDMI (active, directly connected)
      HDMI2,       -- External (optional)
      HDMI3,       -- External (optional)
      Analog,      -- VGA port
      others => Disabled);

end GMA.Mainboard;
