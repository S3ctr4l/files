# NUCLEAR FIRMWARE FORENSICS & COREBOOT PORTING SUITE

**Maximum-depth firmware extraction, analysis, and automated coreboot reconstruction**

---

## 🎯 WHAT IS THIS?

A two-part industrial-grade firmware forensics toolkit designed for **security researchers**, **firmware developers**, and **coreboot porters**. This automates the complete process of:

1. **Extracting EVERYTHING** from x86 firmware (Part 1)
2. **Analyzing, vulnerability scanning, and reconstructing** coreboot ports (Part 2)

**Target Platform:** HP IQ526 (Intel GM45/ICH9M) — but adaptable to any x86 platform

---

## 📦 WHAT'S INCLUDED

### Part 1: Nuclear Extraction (`Dump.sh`)
**1,742 lines of surgical firmware extraction**

Extracts **26 categories** of platform data:
- Complete SPI flash dump with verification
- ALL CPU MSRs (Model-Specific Registers)
- Complete GPIO pad configuration
- Full ACPI table set with decompilation
- Intel ME/CSME analysis
- EC (Embedded Controller) RAM dump
- Complete UEFI variables
- Secure Boot key chain
- TPM measurements
- PCI extended configuration space
- Memory timing (SPD dumps)
- Bootloader configuration
- Storage firmware versions
- Network card EEPROMs
- USB descriptors
- Audio codec registers
- Sensor readings
- Power management state
- SMM (System Management Mode) analysis (invasive)
- Physical memory dumps (invasive)

**Features:**
- ✅ Idempotent execution (resume-safe)
- ✅ State tracking
- ✅ Parallel-safe
- ✅ Comprehensive logging
- ✅ SHA256/MD5 checksums
- ✅ Argument parsing (--invasive, --dry-run)

### Part 2: Analysis & Reconstruction (`Analyze_and_Reconstruct_NUCLEAR.sh`)

**Advanced firmware analysis and automated coreboot porting**

**5 Comprehensive Phases:**

1. **Binary Firmware Analysis**
   - Entropy analysis (detect encryption/compression)
   - String categorization (UEFI modules, PCI IDs, crypto material)
   - Signature scanning (Intel FD, ACPI, coreboot)
   - Firmware layout detection
   - ME region analysis

2. **Advanced Pattern Recognition**
   - GPIO pattern extraction with clustering
   - Memory map reconstruction from multiple sources
   - PCI device tree reconstruction
   - ACPI method call graph generation

3. **Comprehensive Vulnerability Scanning**
   - Intel ME CVE database check (CVE-2017-5689, CVE-2018-3627, etc.)
   - UEFI vulnerability patterns (BootHole, LogoFAIL, etc.)
   - SMM security assessment
   - Boot security features audit
   - Automated CVE summary

4. **Automated Coreboot Reconstruction**
   - Generates complete board port skeleton
   - Auto-creates Kconfig, devicetree.cb, gpio.c
   - Build automation scripts
   - QEMU test infrastructure

5. **Report Generation**
   - Interactive HTML dashboard
   - JSON for programmatic access
   - Markdown executive summary
   - PDF export (optional)

### Companion Tools

#### `gpio_converter.py`
Converts `inteltool` GPIO dumps to coreboot pad configuration format.

```bash
./gpio_converter.py inteltool_gpio.txt -o gpio.c
```

**Features:**
- Automatic pad mode detection (GPI/GPO/Native Function)
- Pull-up/pull-down detection
- Complete coreboot macro generation

#### `ec_reverse_engineer.py`
Extracts EC commands from ACPI tables and SPI dumps.

```bash
./ec_reverse_engineer.py --acpi DSDT.dsl --spi firmware.bin -o ec_commands.h
```

**Features:**
- ACPI method parsing
- EC query event extraction
- Command frequency analysis
- Auto-generates C header file

---

## 🚀 QUICK START

### Prerequisites

```bash
# Arch Linux (target platform)
sudo pacman -S flashrom dmidecode pciutils usbutils acpica \
               msr-tools i2c-tools cpuid python3 git gcc make

# Optional for reports
sudo pacman -S pandoc wkhtmltopdf
```

### Part 1: Extract Firmware

```bash
# Safe mode (read-only, skips /dev/mem)
sudo ./Dump.sh

# Nuclear mode (includes SMM/memory dumps - can hang system!)
sudo ./Dump.sh --invasive

# Test run
sudo ./Dump.sh --dry-run
```

**Output:** `~/coreboot_artifacts/` with 26 subdirectories

**Runtime:** 15-30 minutes (safe mode), 45-60 minutes (invasive)

### Part 2: Analyze & Reconstruct

```bash
# Full analysis + coreboot reconstruction
./Analyze_and_Reconstruct_NUCLEAR.sh ~/coreboot_artifacts

# Only vulnerability scan
./Analyze_and_Reconstruct_NUCLEAR.sh --scan-only

# Only coreboot reconstruction
./Analyze_and_Reconstruct_NUCLEAR.sh --reconstruct-only
```

**Output:**
- `analysis/` - Pattern recognition, string analysis
- `security_assessment/` - CVE database, vulnerability scans
- `reconstruction/` - Complete coreboot board port
- `reports/` - HTML dashboard, JSON, PDF

**Runtime:** 5-10 minutes

---

## 📊 OUTPUT STRUCTURE

```
~/coreboot_artifacts/
├── spi/                    # SPI flash dumps
│   ├── firmware_full.bin   # Complete dump
│   ├── region_bios.bin     # BIOS region
│   ├── region_me.bin       # ME region
│   └── *.sha256            # Checksums
├── acpi/                   # ACPI tables
│   ├── *.bin               # Binary tables
│   ├── *.dsl               # Decompiled source
│   └── ec_gpe_methods.txt  # EC/GPE analysis
├── cpu/                    # CPU configuration
│   ├── msr_cpu*.txt        # MSR dumps per core
│   └── turbostat.txt       # P/C-state analysis
├── gpio/                   # GPIO configuration
│   └── inteltool_gpio.txt  # Complete pad config
├── me/                     # Intel ME analysis
│   ├── intelmetool_*.txt   # ME tool outputs
│   └── me_cleaner_*.txt    # me_cleaner analysis
├── pci/                    # PCI enumeration
│   ├── pci_full_hex_dump.txt  # Extended config space
│   └── pci_tree.txt        # Device hierarchy
├── secure_boot/            # Secure Boot keys
├── tpm/                    # TPM measurements
├── analysis/               # Part 2: Analysis
│   ├── binary_analysis/
│   ├── patterns/
│   └── string_analysis/
├── reconstruction/         # Part 2: Coreboot port
│   └── mainboard/hp_iq526/
│       ├── Kconfig
│       ├── devicetree.cb
│       ├── gpio.c
│       └── Makefile.inc
├── security_assessment/    # Part 2: Vulnerability scans
│   ├── cve_scan/
│   └── vulnerability_summary.txt
└── reports/                # Part 2: Reports
    ├── html/index.html
    ├── json/analysis_results.json
    └── markdown/EXECUTIVE_SUMMARY.md
```

---

## ⚠️ SAFETY & LEGAL

### Safe Operations (Default Mode)
- ✅ Read-only hardware access
- ✅ No firmware writes
- ✅ Cannot brick system
- ✅ All PCI/USB/ACPI enumeration is safe
- ✅ SPI flash reads are safe

### Invasive Operations (`--invasive` flag)
- ⚠️ `/dev/mem` reads (SMM region access)
- ⚠️ SuperIO port probing (may trigger watchdogs)
- ⚠️ Physical memory dumps (can hang system)
- ⚠️ Deep EC RAM scanning

**DO NOT run invasive mode on:**
- Production systems
- Systems without recovery plan
- Systems without external programmer backup

### Legal Notice
This toolkit is for **legitimate security research** and **coreboot development** on hardware you own. Unauthorized firmware modification may void warranties or violate laws.

**Use cases:**
- ✅ Security research on owned hardware
- ✅ Coreboot porting for personal use
- ✅ Firmware vulnerability assessment
- ✅ Academic research
- ❌ Unauthorized system access
- ❌ Warranty fraud
- ❌ Malicious firmware injection

---

## 🔧 ADVANCED USAGE

### Using GPIO Converter

```bash
# Extract GPIO config
sudo inteltool -g > gpio_dump.txt

# Convert to coreboot format
./gpio_converter.py gpio_dump.txt -o mainboard/gpio.c
```

### Using EC Reverse Engineer

```bash
# Decompile ACPI first
iasl -d DSDT.bin

# Extract EC commands
./ec_reverse_engineer.py --acpi DSDT.dsl \
                         --spi firmware_full.bin \
                         -o ec_commands.h \
                         --analyze
```

### Building Coreboot

```bash
cd ~/coreboot_artifacts/reconstruction
./build_coreboot.sh

# Follow prompts to:
# 1. Clone/update coreboot
# 2. Copy board files
# 3. Configure (menuconfig)
# 4. Build
```

---

## 🐛 TROUBLESHOOTING

### "SPI flash read failed"
- Run as root: `sudo ./Dump.sh`
- Check BIOS settings for flash protection
- May need external programmer for locked systems

### "ME region not found"
- Platform may not have ME (older/AMD systems)
- Check if ME is disabled in BIOS

### "Permission denied" for MSR access
- Load module: `sudo modprobe msr`
- Check kernel lockdown: `cat /sys/kernel/security/lockdown`

### "Build failed" in coreboot
- Check coreboot version compatibility
- May need FSP/ME blobs from vendor firmware
- Review build logs in reconstruction/

---

## 📚 FURTHER READING

### Coreboot Documentation
- https://doc.coreboot.org/
- https://review.coreboot.org/

### Firmware Security
- NIST SP 800-193: Platform Firmware Resiliency Guidelines
- UEFI Security Guidelines

### Tools Used
- flashrom: https://flashrom.org/
- inteltool (coreboot util)
- acpica: https://acpica.org/
- me_cleaner: https://github.com/corna/me_cleaner

---

## 🤝 CONTRIBUTING

This is a research toolkit. If you enhance it:
- Add more platform support
- Improve pattern recognition
- Expand vulnerability databases
- Enhance automation

Share improvements via coreboot mailing list or GitHub.

---

## 📄 LICENSE

**GPL-2.0-only** (matching coreboot)

Tools are provided "as is" without warranty. Use at your own risk.

---

## ✨ CREDITS

Developed for **legitimate firmware research** and **coreboot porting**.

Built on shoulders of giants:
- coreboot community
- flashrom developers
- Intel datasheets (publicly available)
- Security researchers who disclosed vulnerabilities

**Target Platform:** HP IQ526 with Intel GM45/ICH9M

---

## 🎓 EDUCATIONAL VALUE

This toolkit demonstrates:
- **x86 firmware architecture** (Flash Descriptor, ME, BIOS regions)
- **PCI configuration space** (standard + extended)
- **ACPI table structure** (RSDP, RSDT, DSDT, SSDTs)
- **GPIO programming** (pad configuration, native functions)
- **MSR programming** (CPU model-specific registers)
- **SMM architecture** (System Management Mode)
- **ME internals** (Intel Management Engine)
- **Coreboot porting** (devicetree, Kconfig, board bring-up)

Perfect for:
- Firmware engineering students
- Security researchers learning low-level security
- Coreboot developers porting new boards
- Reverse engineers studying x86 platforms

---

**Ready to extract EVERYTHING from your firmware?**

```bash
sudo ./Dump.sh
./Analyze_and_Reconstruct_NUCLEAR.sh
```

**Questions? Check the HTML report after Part 2.**
