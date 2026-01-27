# NUCLEAR EXTRACTION - QUICKSTART

## 60-Second Setup

```bash
# 1. Download script
cd /home/open/Programs/Hp_Coreboot_IQ526
# (script should be present as Dump.sh)

# 2. Verify prerequisites
sudo pacman -S --needed flashrom dmidecode acpica pciutils i2c-tools msr-tools

# 3. Check disk space
df -h $HOME  # Need 10GB+ free

# 4. Backup critical data (if running --invasive)
# System may hang during SMM access
```

## Basic Execution (Safe)

```bash
# Safe read-only extraction (30-60 min)
sudo ./Dump.sh

# Monitor in another terminal
tail -f ~/coreboot_artifacts/logs/run.log
```

## Advanced Execution (Risky)

```bash
# Full nuclear mode with invasive operations (60-120 min)
# WARNING: May hang system during SMM/memory access
sudo ./Dump.sh --invasive
```

## Quick Validation

```bash
# Check summary
cat ~/coreboot_artifacts/logs/summary.txt

# Verify key files
ls -lh ~/coreboot_artifacts/spi/firmware_full.bin     # Must exist
ls -lh ~/coreboot_artifacts/acpi/DSDT.dsl             # Must exist  
ls -lh ~/coreboot_artifacts/gpio/inteltool_gpio.txt   # Must exist
```

## Priority Artifacts (Copy These First)

```bash
cd ~/coreboot_artifacts

# Top 5 Critical Files
cp spi/firmware_full.bin /path/to/backup/
cp acpi/DSDT.dsl /path/to/backup/
cp intel/inteltool_all.txt /path/to/backup/
cp gpio/inteltool_gpio.txt /path/to/backup/
cp memory/dmidecode_raw.bin /path/to/backup/
```

## Flash Image Analysis (First Priority)

```bash
cd ~/coreboot_artifacts/spi

# Decode descriptor
ifdtool -d firmware_full.bin

# Extract regions
ifdtool -x firmware_full.bin
# Creates: flashregion_0_flashdescriptor.bin
#          flashregion_1_bios.bin
#          flashregion_2_intel_me.bin
#          flashregion_3_gbe.bin (if present)

# Analyze ME
python3 /home/open/Programs/Hp_Coreboot_IQ526/util/me_cleaner/me_cleaner.py -c firmware_full.bin
```

## ACPI Extraction (Second Priority)

```bash
cd ~/coreboot_artifacts/acpi

# Find EC definition
grep -A 100 "Device (EC" DSDT.dsl > ec_definition.txt

# Find GPIO calls
grep "GPIO" DSDT.dsl | sort -u > gpio_references.txt

# Extract power management
grep -E "_PTS|_WAK|_S[0-5]_" DSDT.dsl > power_methods.txt
```

## GPIO Mapping (Third Priority)

```bash
cd ~/coreboot_artifacts/gpio

# Parse into groups
grep "GPIO" inteltool_gpio.txt | awk '{print $1, $NF}' | sort -n > gpio_values.txt

# Identify active pins
grep -E "GPI|GPO" inteltool_gpio.txt > gpio_active.txt
```

## Create Archive for Sharing

```bash
cd ~
tar -czf iq526_firmware_$(date +%Y%m%d).tar.gz \
  coreboot_artifacts/spi/{firmware_full.bin,flashregion_*.bin,flash_descriptor_decode.txt} \
  coreboot_artifacts/acpi/{DSDT.dsl,SSDT*.dsl,acpidump_all.dat} \
  coreboot_artifacts/intel/inteltool_all.txt \
  coreboot_artifacts/gpio/inteltool_gpio.txt \
  coreboot_artifacts/memory/{dmidecode_raw.bin,memory_info.txt} \
  coreboot_artifacts/pci/pci_full_hex_dump.txt \
  coreboot_artifacts/logs/summary.txt

# Size check (should be 8-15MB)
ls -lh iq526_firmware_*.tar.gz
```

## Troubleshooting

**Flashrom fails:**
```bash
# Check hardware
lspci | grep ISA
dmesg | grep -i spi

# Try force (careful)
sudo flashrom -p internal:laptop=force_I_want_a_brick -r test.bin
```

**ACPI decompilation errors:**
```bash
# Update iasl
sudo pacman -S acpica

# Manual decompile
iasl -d ~/coreboot_artifacts/acpi/DSDT.dat
```

**SuperIO not found:**
```bash
# Load modules
sudo modprobe i2c-i801 i2c-dev

# Manual probe (RISKY)
sudo /home/open/Programs/Hp_Coreboot_IQ526/util/superiotool/superiotool -dV
```

## Next Steps

1. **Validate extraction:**
   - Review summary report
   - Check all critical files exist
   - Verify checksums

2. **Analyze flash image:**
   - Decode descriptor
   - Extract ME region
   - Locate VBT

3. **Parse ACPI:**
   - Extract EC definition
   - Map GPIO pins
   - Document power methods

4. **Begin coreboot port:**
   - Create board directory
   - Configure flash layout
   - Build initial devicetree

## Emergency Recovery

**If system hangs during --invasive mode:**

1. Hard power off (hold power button)
2. Restart normally
3. Re-run script - it will resume from last completed phase
4. Skip invasive mode if unstable

**If you accidentally corrupted something:**

All extraction is READ-ONLY. The script does NOT write to flash or modify system files. At worst, you need to clean up `~/coreboot_artifacts/` and re-run.

## Key Reminders

- ✓ Script is READ-ONLY (no flash writes)
- ✓ Idempotent (can resume after crashes)
- ✓ State-tracked (won't re-run completed phases)
- ✗ Do NOT flash untested coreboot images
- ✗ Do NOT modify script without bash validation
- ✗ Do NOT run without sudo (hardware access required)

## Support

- Script issues: Check `~/coreboot_artifacts/logs/run.log`
- Coreboot porting: https://doc.coreboot.org
- GM45 docs: https://review.coreboot.org
- IRC: #coreboot on libera.chat

