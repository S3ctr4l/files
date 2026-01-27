# FIRMWARE ARTIFACT ANALYSIS GUIDE
## From Raw Data to Coreboot Configuration

### Flash Image Deep Dive

#### 1. Flash Descriptor Analysis
```bash
cd ~/coreboot_artifacts/spi

# Parse descriptor regions
ifdtool -d firmware_full.bin | tee flash_analysis.txt

# Expected output format:
# FLMAP0:    0x02040003
# FLMAP1:    0x12100206  
# FLMAP2:    0x00210120
# FLREG0(Descriptor): 0x00000fff
# FLREG1(BIOS):       0x07ff0200
# FLREG2(ME):         0x001f0001
# FLREG3(GbE):        0x00000000
# FLREG4(Platform):   0x00000000
```

**Key Information Extraction:**
- **Flash Size**: Calculate from FLREG addresses
- **BIOS Region**: Start/end addresses for coreboot
- **ME Region**: Required blob location
- **Descriptor Locks**: Write protection status

#### 2. ME Firmware Analysis
```bash
# Detailed ME inspection
python3 /home/open/Programs/Hp_Coreboot_IQ526/util/me_cleaner/me_cleaner.py \
    -c firmware_full.bin | tee me_analysis.txt

# Look for:
# - ME version (should be ME 5.x for ICH9M)
# - Partition structure
# - Potential neutering feasibility
```

**GM45/ICH9M Specific:**
- ME version 5.x is typical
- Can often be neutralized with me_cleaner
- Must preserve descriptor and ME region structure
- Flash write protection often in descriptor

#### 3. BIOS Region Contents
```bash
# Extract BIOS region
dd if=firmware_full.bin of=bios_region.bin \
   bs=1 skip=$((0x200000)) count=$((0x600000))

# Scan for option ROMs
strings bios_region.bin | grep -i "bios\|rom\|pci"

# Look for embedded microcode
# Typically at end of BIOS region or in FIT table
```

### ACPI Table Processing

#### 1. DSDT Decompilation & EC Extraction
```bash
cd ~/coreboot_artifacts/acpi

# Primary DSDT analysis
iasl -d DSDT.dat

# Extract EC (Embedded Controller) definitions
grep -A 200 "Device (EC" DSDT.dsl > ec_device.txt
grep -A 100 "OperationRegion.*EC" DSDT.dsl > ec_regions.txt

# Critical EC information:
# - EC I/O ports (usually 0x62/0x66)
# - EC RAM field layout
# - EC methods (_REG, _GPE, _Qxx)
```

**Example EC Region:**
```
OperationRegion (ERAM, EmbeddedControl, 0x00, 0xFF)
Field (ERAM, ByteAcc, Lock, Preserve)
{
    Offset (0x04), 
    CMD,    8,      // EC command port
    CDT,    8,      // EC data port
    ...
}
```

#### 2. GPIO via ACPI
```bash
# Extract GPIO method calls
grep -h "_SB.PCI0.LPCB.GPIO" DSDT.dsl SSDT*.dsl > gpio_acpi_calls.txt

# Find GPIO pin assignments
grep -E "GPI[OE][0-9]+" *.dsl | sort -u > gpio_pins.txt
```

#### 3. Power Management
```bash
# Extract _PTS (Prepare To Sleep)
grep -A 50 "Method (_PTS" DSDT.dsl > pts_method.txt

# Extract _WAK (Wake)
grep -A 50 "Method (_WAK" DSDT.dsl > wak_method.txt

# S-state definitions
grep "_S[0-5]_" DSDT.dsl > sleep_states.txt
```

### GPIO Configuration Mapping

#### Intel GM45 GPIO Layout
```bash
cd ~/coreboot_artifacts/gpio

# Parse inteltool GPIO output
cat > parse_gpio.py << 'PYGPIO'
#!/usr/bin/env python3
import re

# GM45 has 3 GPIO groups:
# - GPIO Set 1: GP0-GP31
# - GPIO Set 2: GP32-GP63  
# - GPIO Set 3: GP64-GP72

gpio_groups = {1: [], 2: [], 3: []}

with open('inteltool_gpio.txt', 'r') as f:
    for line in f:
        # Match: GPIO23: 0x12345678
        match = re.search(r'GPIO(\d+).*?:\s*(0x[0-9a-fA-F]+)', line)
        if match:
            num = int(match.group(1))
            val = match.group(2)
            
            # Determine group
            if num <= 31:
                group = 1
            elif num <= 63:
                group = 2
            else:
                group = 3
                
            gpio_groups[group].append((num, val))

# Output for coreboot devicetree
for group, gpios in gpio_groups.items():
    print(f"\n# GPIO Set {group}")
    for num, val in sorted(gpios):
        print(f'register "gpio_base{group}.gp{num % 32}" = "{val}"')
PYGPIO

python3 parse_gpio.py > gpio_devicetree.txt
```

**GPIO Register Decoding:**
```
Bit 31    : GPIO Level (0=Low, 1=High)
Bit 30    : GPIO Output/Input (0=Output, 1=Input)  
Bit 29-28 : Reserved
Bit 27-26 : GPIO Trigger (00=Level, 01=Edge, 10=Disabled)
Bit 25-24 : GPIO Polarity
...
```

### Memory Configuration

#### 1. SPD Decode
```bash
cd ~/coreboot_artifacts/spd

# Decode each DIMM
for spd in dimm*.bin; do
    echo "=== Analyzing $spd ==="
    decode-dimms < "$spd" | tee "${spd}.decoded"
    
    # Extract key parameters:
    # - Memory type (DDR2/DDR3)
    # - Speed (800/1066/1333 MHz)
    # - Timings (CAS, tRCD, tRP, tRAS)
    # - Density and organization
done
```

#### 2. Memory Initialization Parameters
```bash
# From SMBIOS
cd ~/coreboot_artifacts/memory
dmidecode -t memory --from-dump dmidecode_raw.bin | tee memory_config.txt

# Extract for devicetree:
grep "Speed:" memory_config.txt
grep "Size:" memory_config.txt
grep "Type:" memory_config.txt
```

**GM45 Memory Controller Config:**
```c
// Typical GM45 DDR2-800 configuration
struct mem_config {
    .dimm_channel0 = {
        .dimm0 = DIMM_INFO(...),  // From SPD
        .dimm1 = DIMM_INFO(...),
    },
    .tCK = TCK_800MHZ,
    .tRAS = 40,  // From SPD
    .tRP  = 15,
    .tRCD = 15,
    .tWR  = 15,
};
```

### PCI Device Mapping

#### 1. Create Device Tree
```bash
cd ~/coreboot_artifacts/pci

# Parse lspci output
cat > create_devicetree.py << 'PYDEV'
#!/usr/bin/env python3
import re

print("chip northbridge/intel/gm45")
print("  device domain 0 on")
print("    device pci 0.0 on end  # Host Bridge")

with open('pci_tree.txt', 'r') as f:
    for line in f:
        # Match: +-00.1  Device Name
        match = re.search(r'[+\-|]+([0-9a-f]{2})\.([0-9a-f])\s+(.*)', line, re.I)
        if match:
            bus = match.group(1)
            func = match.group(2)
            name = match.group(3).strip()
            
            # Convert to decimal
            dev = int(bus, 16)
            fn = int(func, 16)
            
            # Filter out bridges (handled specially)
            if 'bridge' not in name.lower():
                print(f"    device pci {dev:#x}.{fn} on end  # {name}")

print("  end")
print("end")
PYDEV

python3 create_devicetree.py > initial_devicetree.cb
```

#### 2. PCI Config Space Analysis
```bash
# Extract subsystem IDs
grep "Subsystem:" pci_kernel_drivers.txt | sort -u

# Extract capability chains
grep -A 5 "Capabilities:" pci_full_hex_dump.txt | head -50

# Identify legacy option ROMs
grep -i "Expansion ROM" pci_full_hex_dump.txt
```

### Video BIOS Table (VBT) Extraction

#### 1. Locate VBT in Flash
```bash
cd ~/coreboot_artifacts/video

# VBT typically has signature "$VBT"
strings ../spi/firmware_full.bin | grep -A 2 "\$VBT"

# Or search for Intel VBT signature
hexdump -C ../spi/firmware_full.bin | grep "56 42 54" | head -5

# Extract VBT region (if found at offset)
# dd if=../spi/firmware_full.bin of=vbt.bin bs=1 skip=OFFSET count=SIZE
```

#### 2. VBT Configuration for Coreboot
```bash
# Copy to coreboot source
cp vbt.bin /home/open/Programs/Hp_Coreboot_IQ526/src/mainboard/hp/iq526/

# Add to devicetree.cb:
# register "gfx.use_spread_spectrum_clock" = "1"
# register "gfx.link_frequency_270_mhz" = "1"
```

### SuperIO / EC Configuration

#### 1. SuperIO Detection
```bash
cd ~/coreboot_artifacts/ec

# Parse superiotool output
grep "Found" superio_registers_full.txt

# Expected for IQ526:
# - Winbond W83627DHG or similar
# - ITE IT8512E/IT8518E EC

# Extract LDN (Logical Device Number) configs
grep -A 10 "LDN 0x" superio_registers_full.txt > ldn_config.txt
```

#### 2. EC RAM Layout
```bash
# Analyze EC RAM dump
hexdump -C ec_ram_dump.bin | less

# Common EC RAM locations:
# 0x00-0x0F: System flags
# 0x10-0x1F: Temperature sensors
# 0x20-0x2F: Fan control
# 0x30-0x3F: Battery status
# 0x40-0x4F: AC adapter status
```

### Microcode Updates

#### 1. Extract from OEM BIOS
```bash
cd ~/coreboot_artifacts/microcode

# Search for microcode signature (0x00000001)
# Microcode typically at end of BIOS region
dd if=../spi/firmware_full.bin bs=1 skip=$((0x600000-0x100000)) | \
   strings | grep -i "intel\|microcode"

# Use iucode_tool if available
iucode_tool -l ../spi/firmware_full.bin
```

#### 2. Download Latest Microcode
```bash
# For GM45 (Core 2 Duo):
# CPU signature: 0x01067A (Penryn)

# Download from Intel or linux-firmware
wget https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/raw/main/intel-ucode/06-17-0a

# Add to coreboot:
cp 06-17-0a /home/open/Programs/Hp_Coreboot_IQ526/3rdparty/intel-microcode/
```

### Creating Coreboot Configuration

#### 1. Initial Kconfig
```bash
cd /home/open/Programs/Hp_Coreboot_IQ526
make menuconfig

# Set:
# - Mainboard vendor: HP
# - Mainboard model: IQ526
# - ROM chip size: 8MB (from flash analysis)
# - Add VGA BIOS: Yes (from extracted VBT)
# - Add Intel ME: Yes (from region_me.bin)
```

#### 2. Devicetree.cb Template
```
chip northbridge/intel/gm45
  device cpu_cluster 0 on
    chip cpu/intel/socket_BGA956
      device lapic 0 on end
    end
  end

  device domain 0 on
    device pci 00.0 on end # Host bridge
    device pci 01.0 on end # PCIe Graphics
    device pci 02.0 on end # Integrated graphics (GMA 4500MHD)
    device pci 02.1 on end # Display controller
    device pci 03.0 off end # ME
    device pci 03.2 off end # ME IDE-R
    device pci 03.3 off end # ME KT
    device pci 19.0 off end # GbE (if present)
    device pci 1a.0 on end # USB
    device pci 1a.1 on end # USB
    device pci 1a.2 on end # USB
    device pci 1a.7 on end # USB EHCI
    device pci 1b.0 on end # HD Audio
    device pci 1c.0 on end # PCIe Port 1
    device pci 1c.1 on end # PCIe Port 2
    device pci 1c.2 off end # PCIe Port 3
    device pci 1c.3 off end # PCIe Port 4
    device pci 1c.4 off end # PCIe Port 5
    device pci 1c.5 off end # PCIe Port 6
    device pci 1d.0 on end # USB
    device pci 1d.1 on end # USB
    device pci 1d.2 on end # USB
    device pci 1d.7 on end # USB EHCI
    device pci 1e.0 on end # PCI bridge
    device pci 1f.0 on # LPC bridge
      chip superio/winbond/w83627dhg
        device pnp 2e.0 on end # FDC
        device pnp 2e.1 on end # Parallel
        device pnp 2e.2 on end # COM1
        device pnp 2e.3 off end # COM2
        device pnp 2e.5 on end # Keyboard
        device pnp 2e.6 off end # SPI
        device pnp 2e.7 on end # GPIO
        device pnp 2e.9 off end # GPIO
        device pnp 2e.a on end # ACPI
        device pnp 2e.b on end # HW Monitor
      end
    end
    device pci 1f.2 on end # SATA (IDE mode)
    device pci 1f.3 on end # SMBus
  end
end
```

### Validation Checklist

Before attempting any flash operation:

- [ ] All critical artifacts extracted
- [ ] Flash descriptor decoded successfully
- [ ] ME region identified and extracted
- [ ] VBT located and validated
- [ ] GPIO configuration mapped
- [ ] Memory timings extracted from SPD
- [ ] ACPI tables decompiled without errors
- [ ] PCI device tree matches hardware
- [ ] SuperIO/EC configuration documented
- [ ] Microcode updates located
- [ ] Coreboot builds without errors
- [ ] Test image created and validated with cbfstool
- [ ] Original BIOS backed up securely
- [ ] Hardware flasher available for recovery

### Common GM45/ICH9M Gotchas

1. **Memory Reference Code (MRC)**
   - GM45 requires MRC blob or native raminit
   - Native raminit exists but may be unstable
   - Extract MRC cache from OEM for faster boot

2. **ME Firmware**
   - Must preserve ME region structure
   - Can neutralize with me_cleaner (recommended)
   - Complete ME removal may prevent boot

3. **VGA BIOS**
   - Required for display init (libgfxinit not complete for GM45)
   - Extract from option ROM region
   - Must match hardware revision

4. **GPIO Configuration**
   - Critical for peripheral functionality
   - Incorrect GPIO can prevent boot or damage hardware
   - Validate against schematic if available

5. **EC/SuperIO**
   - Fan control dependencies
   - Keyboard/mouse routing
   - Power button handling

