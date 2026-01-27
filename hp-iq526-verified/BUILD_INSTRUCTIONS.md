# HP TouchSmart IQ526 - Coreboot Build Instructions

## Prerequisites

```bash
# Install build dependencies (Arch Linux)
sudo pacman -S base-devel git python nasm iasl

# Clone coreboot
git clone https://review.coreboot.org/coreboot
cd coreboot
git submodule update --init --checkout
```

## Install Board Files

```bash
# Copy mainboard files
cp -r hp-iq526-verified/src/mainboard/hp/iq526 src/mainboard/hp/

# Add to HP Kconfig (add this line to src/mainboard/hp/Kconfig)
echo 'source "src/mainboard/hp/iq526/Kconfig"' >> src/mainboard/hp/Kconfig
```

## Build Toolchain

```bash
make crossgcc-i386 CPUS=$(nproc)
```

## Configure

```bash
make menuconfig
```

### Required Settings

```
Mainboard --->
    Mainboard vendor (HP)
    Mainboard model (TouchSmart IQ526)

Chipset --->
    [*] Include CPU microcode in CBFS

Devices --->
    Graphics initialization (Use libgfxinit)
    Display --->
        Framebuffer mode (Linear "high-resolution" framebuffer)
    [*] Add a VGA BIOS image
        (pci10de,06e9.rom) VGA BIOS path and target (NVIDIA optional)

Payload --->
    Add a payload (SeaBIOS)
    SeaBIOS version (1.16.x)
```

## Build

```bash
make -j$(nproc)
```

Output: `build/coreboot.rom` (1MB)

## Verify Build

```bash
# Check ROM size
ls -la build/coreboot.rom
# Should be 1048576 bytes (1MB)

# Check CBFS contents
./build/cbfstool build/coreboot.rom print
```

## Flash

### Backup First!
```bash
# ALWAYS backup before flashing!
sudo flashrom -p internal -r backup_before_coreboot.rom
sudo flashrom -p internal -r backup_verify.rom
sha256sum backup_before_coreboot.rom backup_verify.rom
# Checksums MUST match!
```

### Internal Flash (BLE=0 allows this)
```bash
# Unload conflicting drivers
sudo modprobe -r nvidia nouveau

# Flash coreboot
sudo flashrom -p internal -w build/coreboot.rom
```

### External Flash (Safer for first attempt)
```bash
# Using CH341A programmer with SOIC-8 clip
flashrom -p ch341a_spi -w build/coreboot.rom
```

## First Boot Testing

### Serial Console (Recommended)
- Connect to COM1 at 0x3F8
- Baud rate: 115200 8N1
- You should see coreboot banner and boot log

### What to Expect
1. Coreboot banner with version
2. Memory detection (2048 MB)
3. PCI device enumeration
4. SeaBIOS payload loading
5. Boot menu

### If No Display
- Check serial console first
- LVDS panel should work with libgfxinit
- If blank, the Intel GMA may need VBT tuning

## Recovery

If system doesn't boot:
1. Use external programmer (CH341A + SOIC-8 clip)
2. Flash backup_before_coreboot.rom
3. Report issue with serial console log

## CPU Cores

The T6600 is a dual-core CPU. Coreboot automatically detects and initializes both cores via:
- CPUID enumeration
- LAPIC/APIC initialization
- MP table generation

No special configuration needed - both cores will be available to the OS.

## Power Management Features

These are enabled by default in coreboot:
- CPU P-states (frequency scaling)
- CPU C-states (idle power saving)
- PCIe ASPM (link power management)

ACPI tables are generated automatically with proper _PSS, _CST methods.
