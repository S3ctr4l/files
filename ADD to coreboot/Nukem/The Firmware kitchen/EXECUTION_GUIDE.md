# NUCLEAR FIRMWARE EXTRACTION - EXECUTION GUIDE
## HP IQ526 (GM45/ICH9M) Coreboot Port Data Collection

### Pre-Execution Checklist

**System Requirements:**
- [ ] Root access confirmed
- [ ] Arch Linux 6.12 LTS kernel
- [ ] Minimum 10GB free space in $HOME
- [ ] System is stable (no critical processes running)
- [ ] Full system backup completed (if running --invasive)

**Recommended Setup:**
```bash
# 1. Verify available disk space
df -h $HOME

# 2. Check kernel version and lockdown status
uname -r
cat /sys/kernel/security/lockdown

# 3. Ensure iomem access is available
ls -l /dev/mem /dev/port

# 4. Verify coreboot util directory exists
ls -la /home/open/Programs/Hp_Coreboot_IQ526/util/
```

### Execution Strategy

**Phase 1: Safe Baseline Collection (30-60 minutes)**
```bash
# Run without --invasive first to gather safe data
sudo ./Dump.sh

# Monitor progress in another terminal
tail -f ~/coreboot_artifacts/logs/run.log

# Check for any immediate failures
grep "FATAL" ~/coreboot_artifacts/logs/run.log
```

**Phase 2: Invasive Deep Dive (60-120 minutes, RISKY)**
```bash
# IMPORTANT: Close all non-essential applications
# Be prepared for system hang - have hard reset ready

sudo ./Dump.sh --invasive

# If system hangs during SMM access, hard reboot and:
# The script will resume from last completed phase
```

**Phase 3: Verification**
```bash
# Check artifact completeness
cat ~/coreboot_artifacts/logs/summary.txt

# Verify critical files exist
ls -lh ~/coreboot_artifacts/spi/firmware_full.bin
ls -lh ~/coreboot_artifacts/acpi/acpidump_all.dat
ls -lh ~/coreboot_artifacts/memory/dmidecode_raw.bin

# Validate checksums
cd ~/coreboot_artifacts
sha256sum -c logs/all_hashes_sha256.txt | grep -i "failed"
```

### Critical Artifacts for Coreboot Porting

**Priority 1 - REQUIRED:**
1. `spi/firmware_full.bin` - Complete OEM BIOS image
2. `spi/region_*.bin` - Flash regions (BIOS, ME, GbE, etc.)
3. `acpi/acpidump_all.dat` - ACPI tables
4. `acpi/*.dsl` - Decompiled ACPI (DSDT, SSDT)
5. `memory/dmidecode_raw.bin` - SMBIOS tables
6. `gpio/inteltool_gpio.txt` - GPIO configuration
7. `intel/inteltool_all.txt` - Complete chipset dump

**Priority 2 - HIGHLY RECOMMENDED:**
8. `pci/pci_full_hex_dump.txt` - All PCI config spaces
9. `video/vbt_*.bin` - Video BIOS tables
10. `ec/superio_registers_full.txt` - SuperIO configuration
11. `ec/ec_ram_dump.bin` - EC RAM snapshot
12. `me/me_cleaner_detailed.txt` - ME region analysis
13. `cpu/msr_cpu*_critical.txt` - Critical MSR values
14. `spd/spd_*.bin` - Memory SPD data

**Priority 3 - USEFUL:**
15. All logs in `logs/`
16. Decompiled ACPI methods in `acpi/*methods.txt`
17. Network card EEPROMs in `network/`
18. Storage controller info in `storage/`

### Post-Extraction Analysis Workflow

**Step 1: Flash Image Analysis**
```bash
cd ~/coreboot_artifacts/spi

# Verify flash image integrity
md5sum firmware_full.bin firmware_full.bin.md5

# Analyze with ifdtool
/home/open/Programs/Hp_Coreboot_IQ526/util/ifdtool/ifdtool -d firmware_full.bin

# Check for ME region
/home/open/Programs/Hp_Coreboot_IQ526/util/ifdtool/ifdtool -x firmware_full.bin

# ME cleaner analysis
python3 /home/open/Programs/Hp_Coreboot_IQ526/util/me_cleaner/me_cleaner.py -c firmware_full.bin
```

**Step 2: ACPI Table Extraction**
```bash
cd ~/coreboot_artifacts/acpi

# Identify key ACPI objects
grep -h "Device (EC" *.dsl
grep -h "Device (PWRB" *.dsl
grep -h "OperationRegion.*EC" *.dsl

# Extract EC field definitions
grep -A 50 "OperationRegion.*EC" DSDT*.dsl > ec_fields.txt

# Find GPIO definitions
grep -h "_GPE\|_Lxx\|_Exx" *.dsl > gpe_methods.txt
```

**Step 3: Memory Configuration**
```bash
cd ~/coreboot_artifacts/memory

# Decode SMBIOS
dmidecode -t memory --from-dump dmidecode_raw.bin

# Check SPD data
cd ../spd
for spd in *.bin; do
    echo "=== $spd ==="
    decode-dimms < "$spd"
done
```

**Step 4: GPIO Mapping**
```bash
cd ~/coreboot_artifacts/gpio

# Extract GPIO pad configuration
grep "GPIO.*:.*0x" inteltool_gpio.txt | sort -t: -k2 > gpio_sorted.txt

# Identify active GPIOs
grep -E "GPIO.*GPI|GPIO.*GPO" inteltool_gpio.txt > gpio_active.txt
```

### Data Package for Coreboot Developers

**Create Compressed Archive:**
```bash
cd ~
tar -czf coreboot_iq526_artifacts_$(date +%Y%m%d).tar.gz \
    coreboot_artifacts/spi/*.bin \
    coreboot_artifacts/spi/*.txt \
    coreboot_artifacts/acpi/*.dat \
    coreboot_artifacts/acpi/*.dsl \
    coreboot_artifacts/memory/dmidecode_raw.bin \
    coreboot_artifacts/gpio/inteltool_gpio.txt \
    coreboot_artifacts/intel/inteltool_all.txt \
    coreboot_artifacts/pci/pci_full_hex_dump.txt \
    coreboot_artifacts/video/vbt_*.bin \
    coreboot_artifacts/ec/*.txt \
    coreboot_artifacts/spd/*.bin \
    coreboot_artifacts/logs/summary.txt

# Verify archive
tar -tzf coreboot_iq526_artifacts_$(date +%Y%m%d).tar.gz | head -20
```

### Troubleshooting Common Issues

**Issue: Flashrom fails with "no EEPROM/flash device found"**
```bash
# Check SPI controller
lspci -vvv | grep -A 10 "ISA bridge"

# Verify kernel modules
lsmod | grep spi
modprobe spi_intel

# Try with force flag (DANGEROUS - use with caution)
sudo flashrom -p internal:laptop=force_I_want_a_brick -r test.bin
```

**Issue: ACPI decompilation fails**
```bash
# Check iasl version
iasl -v

# Try manual decompilation
cd ~/coreboot_artifacts/acpi
for table in *.dat; do
    iasl -d "$table" 2>&1 | tee "${table}.iasl.log"
done
```

**Issue: SuperIO not detected**
```bash
# Try manual port probe (RISKY)
sudo /home/open/Programs/Hp_Coreboot_IQ526/util/superiotool/superiotool -d -V

# Check if EC is at standard port
sudo outb 0x2e 0x87  # Enter config mode
sudo outb 0x2e 0x01  # Exit config mode
```

**Issue: Missing MSR values**
```bash
# Check if msr module is loaded
lsmod | grep msr
sudo modprobe msr

# Test MSR access
sudo rdmsr 0x8B  # IA32_BIOS_SIGN_ID (microcode version)
```

### Integration with Coreboot Build

**Step 1: Create Board Directory Structure**
```bash
cd /home/open/Programs/Hp_Coreboot_IQ526
mkdir -p src/mainboard/hp/iq526

# Copy template from similar board
cp -r src/mainboard/lenovo/x200/* src/mainboard/hp/iq526/
```

**Step 2: Configure Flash Layout**
```bash
# Use ifdtool output to create flash layout
cd ~/coreboot_artifacts/spi
cat flash_descriptor_decode.txt

# Create coreboot flashmap
cat > /home/open/Programs/Hp_Coreboot_IQ526/src/mainboard/hp/iq526/board.fmd << 'FLASHMAP'
FLASH@0xff800000 0x800000 {
    SI_DESC@0x0 0x1000
    SI_ME@0x1000 0x1ff000
    SI_BIOS@0x200000 0x600000 {
        RW_MRC_CACHE@0x0 0x10000
        COREBOOT(CBFS)@0x10000 0x5f0000
    }
}
FLASHMAP
```

**Step 3: Extract GPIO Configuration**
```bash
# Parse inteltool output for devicetree
cd ~/coreboot_artifacts/gpio
python3 << 'PYGPIO'
import re

with open('inteltool_gpio.txt', 'r') as f:
    for line in f:
        match = re.search(r'GPIO(\d+).*:\s*(0x[0-9a-f]+)', line, re.I)
        if match:
            gpio_num = match.group(1)
            value = match.group(2)
            print(f"register \"gpio{gpio_num}\" = \"{value}\"")
PYGPIO
```

**Step 4: Extract ACPI Device Configuration**
```bash
# Create device tree stubs from ACPI
cd ~/coreboot_artifacts/acpi
grep -h "Device (" DSDT*.dsl | sort -u > devices.txt

# Map to coreboot devicetree
# This requires manual interpretation based on _ADR values
```

### Next Steps After Data Collection

1. **Analyze Flash Regions**
   - Determine exact flash chip model
   - Map ME region boundaries
   - Identify VGA BIOS location
   - Check for write protection

2. **Create Initial Devicetree**
   - Map PCI devices to coreboot structure
   - Configure GPIO pads
   - Set up memory timings
   - Define ACPI devices

3. **Extract Required Blobs**
   - ME firmware (or neutered version)
   - VGA BIOS (for display init)
   - Microcode updates
   - MRC cache (optional)

4. **Build Test Image**
   - Configure with make menuconfig
   - Build with make -j$(nproc)
   - Validate with cbfstool
   - **DO NOT FLASH YET** - simulate first

5. **Simulation Testing**
   - Use QEMU with extracted ROM
   - Validate POST sequence
   - Check for missing init
   - Debug with coreboot logging

### Safety Reminders

⚠️ **NEVER flash an untested image to hardware**
⚠️ **Always have a hardware flasher ready for recovery**
⚠️ **Test in QEMU first**
⚠️ **Keep original OEM BIOS backup**
⚠️ **Document every change**

### Support Resources

- Coreboot documentation: https://doc.coreboot.org
- GM45 chipset guide: https://01.org/linuxgraphics/documentation
- ICH9M datasheet: Intel PCH documentation
- Coreboot mailing list: coreboot@coreboot.org
- IRC: #coreboot on libera.chat

