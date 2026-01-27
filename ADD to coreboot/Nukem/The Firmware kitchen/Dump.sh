#!/bin/bash
# ============================================================
# NUCLEAR-GRADE Firmware Extraction Pipeline
# Extracts EVERYTHING possible from x86 platform
# WARNING: Some phases can destabilize system
# ============================================================

set -Eeuo pipefail

UTILDIR="/home/open/Programs/Hp_Coreboot_IQ526/util"
WORKDIR="$HOME/coreboot_artifacts"
LOGDIR="$WORKDIR/logs"
STATEDIR="$WORKDIR/state"
DRY_RUN=1
INVASIVE_MODE=0  # Set to 1 to enable risky operations

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --invasive)
            INVASIVE_MODE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --help)
            echo "NUCLEAR FIRMWARE EXTRACTION PIPELINE"
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --invasive    Enable invasive operations (SMM, /dev/mem dumps)"
            echo "  --dry-run     Test mode - log commands without executing"
            echo "  --help        Show this help message"
            echo ""
            echo "Output: All artifacts saved to ~/coreboot_artifacts/"
            echo ""
            echo "WARNING: --invasive mode can:"
            echo "  - Hang the system (SMM access)"
            echo "  - Trigger watchdogs (SuperIO probing)"
            echo "  - Expose sensitive data (memory dumps)"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

mkdir -p "$WORKDIR"/{spi,acpi,pci,gpio,ec,spd,me,intel,vbt,nvram,video,cbfs,memory,uefi,tpm,usb,storage,network,secure_boot,bootloader,cpu,peripheral,smm,pmc,chipset,security,kernel,i2c,microcode,thunderbolt,audio,sensors,firmware_blobs,mmio,cache,pstate,uncore,dma,ipc,clock,vrm,boot_guard,sgx,cse,fsp}

# ---------------- COLORS ----------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# ---------------- LOGGING ----------------
log() { echo -e "[$(date +%F_%T)] $*" | tee -a "$LOGDIR/run.log"; }
die() { log "${RED}FATAL:${NC} $*"; exit 1; }
warn() { log "${YELLOW}WARN:${NC} $*"; }
info() { log "${BLUE}INFO:${NC} $*"; }
danger() { log "${MAGENTA}DANGER:${NC} $*"; }
state_mark() { touch "$STATEDIR/$1.done"; }
state_done() { [[ -f "$STATEDIR/$1.done" ]]; }

run() {
    log "CMD: $*"
    [[ "$DRY_RUN" == "1" ]] && return 0
    eval "$@" 2>&1 | tee -a "$LOGDIR/${FUNCNAME[1]:-default}.log" || warn "Command failed: $*"
}

safe_run() {
    if [[ "$INVASIVE_MODE" == "1" ]]; then
        run "$@"
    else
        warn "SKIPPED (invasive): $*"
    fi
}

require_root() {
    [[ $EUID -ne 0 ]] && die "Run as root (required for hardware access)"
}

check_tool() {
    command -v "$1" &>/dev/null || { warn "Missing tool: $1"; return 1; }
    return 0
}

install_missing_tools() {
    log "${YELLOW}Installing additional tools...${NC}"

    # Core utilities
    local tools=(
        "msr-tools" "i2c-tools" "pciutils" "usbutils" "dmidecode"
        "acpica" "flashrom" "nvme-cli" "smartmontools" "ethtool"
        "cpuid" "memtester" "stress-ng" "lm_sensors"
    )

    for tool in "${tools[@]}"; do
        if ! pacman -Qi "$tool" &>/dev/null; then
            info "Installing $tool..."
            run sudo pacman -S --noconfirm "$tool" 2>/dev/null || warn "Failed to install $tool"
        fi
    done

    # AUR tools
    local aur_tools=("chipsec" "rweverything" "firmware-mod-kit")
    for tool in "${aur_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            info "Attempting to install $tool from AUR..."
            run yay -S --noconfirm "$tool" 2>/dev/null || warn "$tool not available"
        fi
    done
}

# ---------------- KERNEL MODULE LOADING ----------------
load_kernel_modules() {
    state_done kernel_mods && return
    log "${YELLOW}Loading required kernel modules...${NC}"

    local modules=(
        "msr" "cpuid" "i2c-dev" "i2c-i801" "eeprom"
        "at24" "i2c-smbus" "mei" "mei_me" "mei_hdcp"
        "intel_pmc_core" "intel_pmc_bxt" "intel_pmt"
        "iTCO_wdt" "intel_rapl_msr"
    )

    for mod in "${modules[@]}"; do
        if ! lsmod | grep -q "^$mod"; then
            run sudo modprobe "$mod" 2>/dev/null || warn "Module $mod not available"
        fi
    done

    state_mark kernel_mods
}

# ---------------- EC TOOL CLEANUP ----------------
ec_tool_cleanup() {
    state_done ectool_cleanup && return
    log "${YELLOW}Resolving ectool conflicts...${NC}"

    if pacman -Qi ectool &>/dev/null; then
        run sudo pacman -Rdd --noconfirm ectool
    fi

    [ -f /usr/bin/ectool ] && run sudo rm -f /usr/bin/ectool

    if ! command -v ectool &>/dev/null; then
        run yay -S --noconfirm fw-ectool-git 2>/dev/null || warn "fw-ectool-git unavailable"
    fi

    state_mark ectool_cleanup
}

# ---------------- BUILD PHASE ----------------
phase_build() {
    state_done build && return
    log "${YELLOW}Building all Coreboot util tools...${NC}"

    BUILD_TOOLS=(
        ifdtool intelmetool me_cleaner inteltool msrtool superiotool
        ectool spdtool spd_tools cbfstool cbmem bucts futility
        intelvbttool acpi nvramtool kbc1126 gpioutil uio_test
        smmstoretool amdfwtool k8resdump
    )

    for tool in "${BUILD_TOOLS[@]}"; do
        if [ -d "$UTILDIR/$tool" ]; then
            cd "$UTILDIR/$tool"
            if [ -f Makefile ]; then
                log "Building $tool..."
                run make clean 2>/dev/null || true
                run make HOSTCC=gcc -j$(nproc) || warn "$tool build failed"
            fi
        fi
    done

    cd "$UTILDIR"
    state_mark build
}

# ---------------- SYSTEM INFO (ENHANCED) ----------------
phase_sysinfo() {
    state_done sysinfo && return
    log "${YELLOW}Gathering comprehensive system info...${NC}"

    run sudo dmidecode --dump-bin "$WORKDIR/memory/dmidecode_raw.bin"
    run sudo dmidecode > "$LOGDIR/dmidecode_full.txt"

    run lspci -vvvnnxxxx > "$WORKDIR/pci/pci_full_hex_dump.txt"
    run lspci -tv > "$WORKDIR/pci/pci_tree.txt"
    run lspci -k > "$WORKDIR/pci/pci_kernel_drivers.txt"

    run lsusb -vvv > "$LOGDIR/usb_devices_verbose.txt"
    run lsusb -t > "$LOGDIR/usb_tree.txt"

    run lscpu --all --extended=CPU,CORE,SOCKET,NODE,BOOK,DRAWER,CACHE,POLARIZATION,ADDRESS,CONFIGURED,ONLINE,MAXMHZ,MINMHZ > "$LOGDIR/lscpu_extended.txt"
    run lscpu --parse > "$LOGDIR/lscpu_parse.txt"

    run lsblk -o +MODEL,SERIAL,VENDOR,TRAN,FSTYPE,UUID > "$WORKDIR/storage/block_devices.txt"
    run blkid > "$WORKDIR/storage/block_ids.txt"

    run dmesg > "$LOGDIR/dmesg_boot.txt"
    run journalctl -b -k > "$LOGDIR/kernel_messages.txt"
    run lsmod > "$LOGDIR/lsmod.txt"

    run cat /proc/cmdline > "$LOGDIR/kernel_cmdline.txt"
    run uname -a > "$LOGDIR/uname.txt"

    state_mark sysinfo
}

# ---------------- SPI / FIRMWARE (NUCLEAR) ----------------
phase_spi() {
    state_done spi && return
    log "${YELLOW}Dumping SPI firmware (all methods + verification)...${NC}"

    # Primary dump
    if run sudo flashrom -p internal -r "$WORKDIR/spi/firmware_full.bin"; then
        run sha256sum "$WORKDIR/spi/firmware_full.bin" > "$WORKDIR/spi/firmware_full.sha256"
        run md5sum "$WORKDIR/spi/firmware_full.bin" > "$WORKDIR/spi/firmware_full.md5"

        # Verification read
        info "Performing verification read..."
        run sudo flashrom -p internal -r "$WORKDIR/spi/firmware_verify.bin"
        if cmp -s "$WORKDIR/spi/firmware_full.bin" "$WORKDIR/spi/firmware_verify.bin"; then
            info "✓ Verification passed - dumps are identical"
            rm "$WORKDIR/spi/firmware_verify.bin"
        else
            warn "Verification FAILED - dumps differ! Check for unstable flash"
        fi

        # Flash descriptor analysis
        if [ -f "$UTILDIR/ifdtool/ifdtool" ]; then
            run "$UTILDIR/ifdtool/ifdtool" -x "$WORKDIR/spi/firmware_full.bin"
            mv flashregion_*.bin "$WORKDIR/spi/" 2>/dev/null || true
            run "$UTILDIR/ifdtool/ifdtool" -d "$WORKDIR/spi/firmware_full.bin" > "$WORKDIR/spi/flash_descriptor_decode.txt"
            run "$UTILDIR/ifdtool/ifdtool" -f "$WORKDIR/spi/flash_descriptor_layout.txt" "$WORKDIR/spi/firmware_full.bin"
        fi

        # Region-specific dumps with retries
        for region in bios me gbe pd ec; do
            for attempt in 1 2 3; do
                if run sudo flashrom -p internal -r "$WORKDIR/spi/region_${region}.bin" --ifd -i "$region"; then
                    break
                else
                    warn "Region $region attempt $attempt failed"
                    sleep 1
                fi
            done
        done

        # Flash chip info
        run sudo flashrom -p internal --flash-name > "$WORKDIR/spi/flash_chip_info.txt"
        run sudo flashrom -p internal --flash-size > "$WORKDIR/spi/flash_size.txt"

        # Lock bit analysis
        run sudo flashrom -p internal --wp-status > "$WORKDIR/spi/flash_wp_status.txt" 2>/dev/null || true

        # SPI controller registers (Intel PCH)
        if [ -r /sys/devices/pci0000:00/0000:00:1f.5 ]; then
            run sudo dd if=/sys/devices/pci0000:00/0000:00:1f.5/config of="$WORKDIR/spi/spi_controller_config.bin" bs=256 count=1 2>/dev/null
        fi
    else
        warn "Flashrom internal read failed - trying alternatives"
    fi

    # External programmer attempts
    for programmer in "ch341a_spi" "dediprog" "buspirate_spi" "ft2232_spi"; do
        if flashrom -p "$programmer" 2>&1 | grep -qi "found"; then
            info "Attempting $programmer dump..."
            run sudo flashrom -p "$programmer" -r "$WORKDIR/spi/firmware_${programmer}.bin"
        fi
    done

    state_mark spi
}

# ---------------- INTEL ME / CSME (DEEP) ----------------
phase_me_csme() {
    state_done me_csme && return
    log "${YELLOW}Extracting Intel ME/CSME (complete analysis)...${NC}"

    # IntelMETool
    if [ -f "$UTILDIR/intelmetool/intelmetool" ]; then
        run sudo "$UTILDIR/intelmetool/intelmetool" -s > "$WORKDIR/me/intelmetool_status.txt"
        run sudo "$UTILDIR/intelmetool/intelmetool" -d > "$WORKDIR/me/intelmetool_detailed.txt"
        run sudo "$UTILDIR/intelmetool/intelmetool" -m > "$WORKDIR/me/intelmetool_memory.txt"
        run sudo "$UTILDIR/intelmetool/intelmetool" -b "$WORKDIR/me/me_binary.bin"
    fi

    # ME Cleaner analysis
    if [ -f "$UTILDIR/me_cleaner/me_cleaner.py" ] && [ -f "$WORKDIR/spi/firmware_full.bin" ]; then
        run python3 "$UTILDIR/me_cleaner/me_cleaner.py" -c "$WORKDIR/spi/firmware_full.bin" > "$WORKDIR/me/me_cleaner_check.txt"
        run python3 "$UTILDIR/me_cleaner/me_cleaner.py" -t "$WORKDIR/spi/firmware_full.bin" > "$WORKDIR/me/me_cleaner_detailed.txt"
        run python3 "$UTILDIR/me_cleaner/me_cleaner.py" -S "$WORKDIR/spi/firmware_full.bin" > "$WORKDIR/me/me_cleaner_summary.txt"
    fi

    # MEI/HECI interface dumps
    for mei in /dev/mei* /dev/mei0; do
        if [ -c "$mei" ]; then
            info "Dumping MEI interface: $mei"
            run sudo dd if="$mei" of="$WORKDIR/me/mei_$(basename $mei)_dump.bin" bs=4096 count=256 2>/dev/null || warn "MEI read failed"
        fi
    done

    # CSE file system extraction (if accessible)
    if check_tool "cse_unpack"; then
        run cse_unpack "$WORKDIR/spi/region_me.bin" "$WORKDIR/cse/" || warn "CSE unpack failed"
    fi

    # ME version from PCI config
    if [ -d /sys/devices/pci0000:00/0000:00:16.0 ]; then
        run sudo dd if=/sys/devices/pci0000:00/0000:00:16.0/config of="$WORKDIR/me/mei_pci_config.bin" bs=256 count=1 2>/dev/null
    fi

    # HECI version command (if mei driver loaded)
    if [ -c /dev/mei0 ]; then
        check_tool "mei-amt-check" && run sudo mei-amt-check > "$WORKDIR/me/amt_status.txt"
    fi

    state_mark me_csme
}

# ---------------- CPU / MSR (COMPLETE) ----------------
phase_cpu_deep() {
    state_done cpu_deep && return
    log "${YELLOW}Deep CPU analysis (all MSRs, cache, ucode)...${NC}"

    # Full CPUID dump
    check_tool cpuid && {
        run cpuid -r > "$WORKDIR/cpu/cpuid_raw.txt"
        run cpuid -1 > "$WORKDIR/cpu/cpuid_verbose.txt"
    }

    # ALL MSRs (expand to 0xFFFF if needed, but 0x2000 covers common)
    if check_tool rdmsr; then
        info "Dumping ALL MSRs (this takes time)..."
        for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
            cpunum=$(basename "$cpu" | sed 's/cpu//')

            # Common MSR ranges
            local msr_ranges=(
                "0x0:0x100"      # Basic MSRs
                "0x100:0x200"    # Extended
                "0x200:0x300"    # MTRR
                "0x300:0x400"    # Perf counters
                "0x400:0x500"    # Power
                "0x600:0x700"    # Thermal
                "0x800:0x900"    # Extended state
                "0xC00:0xD00"    # Arch perfmon
                "0x1A0:0x1B0"    # Turbo
                "0x3A:0x3B"      # Feature control
                "0x8B:0x8C"      # Microcode
            )

            for range in "${msr_ranges[@]}"; do
                start=${range%%:*}
                end=${range##*:}
                for ((msr=start; msr<end; msr++)); do
                    printf "0x%X: " "$msr" >> "$WORKDIR/cpu/msr_cpu${cpunum}_range.txt"
                    sudo rdmsr -p "$cpunum" "$(printf '0x%X' $msr)" 2>/dev/null >> "$WORKDIR/cpu/msr_cpu${cpunum}_range.txt" || echo "N/A" >> "$WORKDIR/cpu/msr_cpu${cpunum}_range.txt"
                done
            done

            # Critical individual MSRs
            local critical_msrs=(
                0x10 0x1A0 0x1B 0x8B 0xC1 0xC2 0xE7 0xE8 0x17F
                0x198 0x199 0x19A 0x1A2 0x1A4 0x3A 0xCE 0x1FC
                0x606 0x610 0x611 0x639 0x64E 0x64F
            )

            for msr in "${critical_msrs[@]}"; do
                printf "MSR 0x%X: " "$msr" >> "$WORKDIR/cpu/msr_cpu${cpunum}_critical.txt"
                sudo rdmsr -p "$cpunum" "$(printf '0x%X' $msr)" 2>/dev/null >> "$WORKDIR/cpu/msr_cpu${cpunum}_critical.txt" || echo "N/A" >> "$WORKDIR/cpu/msr_cpu${cpunum}_critical.txt"
            done
        done
    fi

    # Cache topology
    run lscpu --caches=NAME,SIZE,TYPE,LEVEL > "$WORKDIR/cpu/cache_topology.txt"
    if [ -d /sys/devices/system/cpu/cpu0/cache ]; then
        for cache in /sys/devices/system/cpu/cpu0/cache/index*; do
            idx=$(basename "$cache")
            {
                echo "=== $idx ==="
                cat "$cache/type" 2>/dev/null
                cat "$cache/size" 2>/dev/null
                cat "$cache/level" 2>/dev/null
                cat "$cache/coherency_line_size" 2>/dev/null
                cat "$cache/ways_of_associativity" 2>/dev/null
            } >> "$WORKDIR/cpu/cache_details.txt"
        done
    fi

    # Microcode
    run grep microcode /proc/cpuinfo > "$WORKDIR/cpu/microcode_version.txt"
    if [ -f /sys/devices/system/cpu/cpu0/microcode/version ]; then
        run cat /sys/devices/system/cpu/cpu0/microcode/version > "$WORKDIR/cpu/microcode_sysfs.txt"
    fi

    # CPU frequency/voltage info
    run cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > "$WORKDIR/cpu/freq_governors.txt" 2>/dev/null || true
    run cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_available_frequencies > "$WORKDIR/cpu/available_freqs.txt" 2>/dev/null || true

    # P-states / C-states
    check_tool turbostat && run sudo turbostat --show=CPU,Avg_MHz,Busy%,Bzy_MHz,TSC_MHz,IPC,IRQ,C1,C1E,C3,C6,C7,Pkg%pc2,Pkg%pc3,Pkg%pc6,Pkg%pc7,PkgWatt -n 1 > "$WORKDIR/cpu/turbostat.txt"

    # Performance monitoring
    if [ -d /sys/devices/system/cpu/cpu0/events ]; then
        run ls -la /sys/devices/system/cpu/cpu0/events/ > "$WORKDIR/cpu/perf_events.txt"
    fi

    state_mark cpu_deep
}

# ---------------- CHIPSET / PCH (COMPLETE) ----------------
phase_chipset_pch() {
    state_done chipset_pch && return
    log "${YELLOW}Extracting ALL chipset/PCH registers...${NC}"

    # InteltTool full dump
    if [ -f "$UTILDIR/inteltool/inteltool" ]; then
        run sudo "$UTILDIR/inteltool/inteltool" -a > "$WORKDIR/intel/inteltool_all.txt"
        run sudo "$UTILDIR/inteltool/inteltool" -g > "$WORKDIR/intel/inteltool_gpio.txt"
        run sudo "$UTILDIR/inteltool/inteltool" -m > "$WORKDIR/intel/inteltool_mchbar.txt"
        run sudo "$UTILDIR/inteltool/inteltool" -p > "$WORKDIR/intel/inteltool_pmbase.txt"
        run sudo "$UTILDIR/inteltool/inteltool" -s > "$WORKDIR/intel/inteltool_spi.txt"
        run sudo "$UTILDIR/inteltool/inteltool" -t > "$WORKDIR/intel/inteltool_tco.txt"
    fi

    # RCBA (Root Complex Base Address) - typical location
    if [ -r /dev/mem ]; then
        info "Attempting RCBA dump..."
        # RCBA is usually at 0xFED1C000 (check lspci for actual address)
        safe_run sudo dd if=/dev/mem of="$WORKDIR/chipset/rcba_dump.bin" bs=4096 count=4 skip=$((0xFED1C000/4096)) 2>/dev/null
    fi

    # PMC (Power Management Controller) registers
    if [ -d /sys/kernel/debug/pmc_core ]; then
        run sudo cat /sys/kernel/debug/pmc_core/pch_ip_power_gating_status > "$WORKDIR/pmc/ip_power_gating.txt" 2>/dev/null || true
        run sudo cat /sys/kernel/debug/pmc_core/ltr_show > "$WORKDIR/pmc/ltr_status.txt" 2>/dev/null || true
        run sudo cat /sys/kernel/debug/pmc_core/slp_s0_residency_usec > "$WORKDIR/pmc/s0_residency.txt" 2>/dev/null || true
    fi

    # P2SB (Primary to Sideband Bridge) - hidden device
    info "Attempting P2SB unhide..."
    safe_run sudo setpci -s 00:1f.1 0xE1.b=0x0  # Unhide P2SB
    if lspci -s 00:1f.1 &>/dev/null; then
        run sudo dd if=/sys/bus/pci/devices/0000:00:1f.1/config of="$WORKDIR/chipset/p2sb_config.bin" bs=256 count=1 2>/dev/null
        safe_run sudo setpci -s 00:1f.1 0xE1.b=0x1  # Re-hide
    fi

    # LPC bridge detailed config
    for lpc_addr in "00:1f.0" "00:1f.2"; do
        if lspci -s "$lpc_addr" &>/dev/null; then
            run sudo dd if=/sys/bus/pci/devices/0000:${lpc_addr//:/:0}/config of="$WORKDIR/chipset/lpc_${lpc_addr//:/_}_full.bin" bs=256 count=1 2>/dev/null

            # LPC decode registers
            for reg in 0x80 0x84 0x88 0x8C 0x90; do
                run sudo setpci -s "$lpc_addr" "$(printf '0x%X' $reg).l" > "$WORKDIR/chipset/lpc_reg_$(printf '%02X' $reg).txt"
            done
        fi
    done

    # HPET registers
    if [ -r /dev/mem ]; then
        safe_run sudo dd if=/dev/mem of="$WORKDIR/chipset/hpet_regs.bin" bs=4096 count=1 skip=$((0xFED00000/4096)) 2>/dev/null
    fi

    # IOAPIC
    if [ -r /sys/kernel/debug/x86/io_apic ]; then
        run sudo cat /sys/kernel/debug/x86/io_apic > "$WORKDIR/chipset/ioapic.txt"
    fi

    state_mark chipset_pch
}

# ---------------- MEMORY CONTROLLER / SPD (DEEP) ----------------
phase_memory_deep() {
    state_done memory_deep && return
    log "${YELLOW}Deep memory controller analysis...${NC}"

    # SPD from all possible slots
    if check_tool i2cdump; then
        for bus in $(seq 0 15); do
            for addr in $(seq 0x50 0x57); do
                run sudo i2cdump -y "$bus" "$addr" b > "$WORKDIR/spd/i2c_bus${bus}_addr${addr}.txt" 2>/dev/null || true
            done
        done
    fi

    # Decode SPD data
    if check_tool decode-dimms; then
        run sudo decode-dimms > "$WORKDIR/spd/decode_dimms.txt"
    fi

    # Memory controller registers (from inteltool)
    if [ -f "$WORKDIR/intel/inteltool_mchbar.txt" ]; then
        grep -E "0x[0-9A-Fa-f]{4}:" "$WORKDIR/intel/inteltool_mchbar.txt" > "$WORKDIR/memory/mc_registers.txt" || true
    fi

    # Memory training data (MRC cache)
    if [ -f /sys/firmware/efi/efivars/MemoryTypeInformation-* ]; then
        run sudo cp /sys/firmware/efi/efivars/MemoryTypeInformation-* "$WORKDIR/memory/memory_type_info.bin"
    fi

    # Look for MRC cache in CBFS
    if [ -f "$WORKDIR/cbfs/extracted/mrc.cache" ]; then
        run cp "$WORKDIR/cbfs/extracted/mrc.cache" "$WORKDIR/memory/"
    fi

    # Physical memory map
    run sudo cat /proc/iomem > "$WORKDIR/memory/iomem.txt"
    run sudo cat /proc/meminfo > "$WORKDIR/memory/meminfo.txt"
    run free -h > "$WORKDIR/memory/free.txt"

    # E820 memory map
    if [ -r /sys/firmware/memmap ]; then
        for entry in /sys/firmware/memmap/*; do
            {
                echo "=== $(basename $entry) ==="
                cat "$entry/start" 2>/dev/null
                cat "$entry/end" 2>/dev/null
                cat "$entry/type" 2>/dev/null
            } >> "$WORKDIR/memory/e820_map.txt"
        done
    fi

    # Memory scrambler seed (if accessible via MSR)
    check_tool rdmsr && {
        run sudo rdmsr -a 0x8B > "$WORKDIR/memory/scrambler_seed.txt" 2>/dev/null || true
    }

    state_mark memory_deep
}

# ---------------- SMM / SMI ANALYSIS (DANGEROUS) ----------------
phase_smm_analysis() {
    state_done smm_analysis && return
    danger "Analyzing SMM/SMI (INVASIVE - can hang system)"

    [[ "$INVASIVE_MODE" != "1" ]] && { warn "Skipping SMM analysis (enable INVASIVE_MODE=1)"; state_mark smm_analysis; return; }

    # SMRAM base detection (usually 0xA0000 or check MSR 0x9E)
    check_tool rdmsr && {
        run sudo rdmsr -a 0x9E > "$WORKDIR/smm/smramc_msr.txt" 2>/dev/null || true
    }

    # SMI statistics (if exposed by kernel)
    if [ -r /sys/kernel/debug/x86/smi_count ]; then
        run sudo cat /sys/kernel/debug/x86/smi_count > "$WORKDIR/smm/smi_count.txt"
    fi

    # Attempt SMRAM dump (VERY RISKY - often locked)
    if [ -r /dev/mem ]; then
        info "Attempting SMRAM dump (may fail due to locks)..."
        safe_run sudo dd if=/dev/mem of="$WORKDIR/smm/smram_A0000.bin" bs=128k count=1 skip=$((0xA0000/131072)) 2>/dev/null
        safe_run sudo dd if=/dev/mem of="$WORKDIR/smm/smram_FED00000.bin" bs=4k count=256 skip=$((0xFED00000/4096)) 2>/dev/null
    fi

    # SMI handlers (if chipsec available)
    if check_tool chipsec_main; then
        safe_run sudo chipsec_main -m common.smm > "$WORKDIR/smm/chipsec_smm.txt"
        safe_run sudo chipsec_main -m common.smrr > "$WORKDIR/smm/chipsec_smrr.txt"
    fi

    state_mark smm_analysis
}

# ---------------- I2C / SMBUS DEEP SCAN ----------------
phase_i2c_scan() {
    state_done i2c_scan && return
    log "${YELLOW}Scanning all I2C/SMBus devices...${NC}"

    # Detect all I2C buses
    check_tool i2cdetect && {
        for bus in /dev/i2c-*; do
            busnum=${bus##*-}
            info "Scanning I2C bus $busnum..."
            run sudo i2cdetect -y "$busnum" > "$WORKDIR/i2c/i2cdetect_bus${busnum}.txt"

            # Dump all detected devices
            for addr in $(seq 0x03 0x77); do
                if sudo i2cget -y "$busnum" "$addr" 0x00 2>/dev/null; then
                    run sudo i2cdump -y "$busnum" "$addr" b > "$WORKDIR/i2c/bus${busnum}_addr$(printf '%02X' $addr).bin"
                fi
            done
        done
    }

    # SMBus-specific (usually i2c-0 or i2c-1)
    if [ -c /dev/smbus ]; then
        run sudo i2cdump -y 0 0x50 b > "$WORKDIR/i2c/smbus_0x50.txt" 2>/dev/null || true
    fi

    state_mark i2c_scan
}

# ---------------- PCI CONFIG SPACE (COMPLETE) ----------------
phase_pci_complete() {
    state_done pci_complete && return
    log "${YELLOW}Dumping ALL PCI config spaces (256 bytes per device)...${NC}"

    # Extended config space (4096 bytes) for PCIe devices
    for dev in /sys/bus/pci/devices/*; do
        bdf=$(basename "$dev")

        # Standard 256-byte config
        run sudo dd if="${dev}/config" of="$WORKDIR/pci/config_${bdf}.bin" bs=256 count=1 2>/dev/null

        # Extended 4K config (PCIe only)
        if [ -f "${dev}/config" ] && [ "$(stat -c%s "${dev}/config")" -ge 4096 ]; then
            run sudo dd if="${dev}/config" of="$WORKDIR/pci/config_extended_${bdf}.bin" bs=4096 count=1 2>/dev/null
        fi

        # Resource mapping
        if [ -f "${dev}/resource" ]; then
            run sudo cat "${dev}/resource" > "$WORKDIR/pci/resource_${bdf}.txt"
        fi

        # Driver info
        if [ -L "${dev}/driver" ]; then
            echo "$(readlink ${dev}/driver)" > "$WORKDIR/pci/driver_${bdf}.txt"
        fi
    done

    # Detailed capability dumps
    run lspci -vvvnnxxxx -D > "$WORKDIR/pci/pci_capabilities_full.txt"

    state_mark pci_complete
}

# ---------------- GPIO (COMPLETE) ----------------
phase_gpio_complete() {
    state_done gpio_complete && return
    log "${YELLOW}Complete GPIO extraction...${NC}"

    # Intel GPIO via inteltool
    if [ -f "$UTILDIR/inteltool/inteltool" ]; then
        run sudo "$UTILDIR/inteltool/inteltool" -g > "$WORKDIR/gpio/inteltool_gpio_full.txt"
    fi

    # GPIO via sysfs
    if [ -d /sys/class/gpio ]; then
        run ls -la /sys/class/gpio > "$WORKDIR/gpio/gpio_sysfs.txt"

        # Export and read all available GPIOs (CAREFUL - can affect hardware)
        if [[ "$INVASIVE_MODE" == "1" ]]; then
            for gpio in /sys/class/gpio/gpiochip*; do
                chip=$(basename "$gpio")
                base=$(cat "$gpio/base")
                ngpio=$(cat "$gpio/ngpio")

                for ((pin=base; pin<base+ngpio; pin++)); do
                    echo "$pin" | sudo tee /sys/class/gpio/export 2>/dev/null || true
                    if [ -d "/sys/class/gpio/gpio${pin}" ]; then
                        {
                            echo "GPIO $pin:"
                            cat "/sys/class/gpio/gpio${pin}/direction" 2>/dev/null
                            cat "/sys/class/gpio/gpio${pin}/value" 2>/dev/null
                        } >> "$WORKDIR/gpio/gpio_${chip}_pin${pin}.txt"
                        echo "$pin" | sudo tee /sys/class/gpio/unexport 2>/dev/null || true
                    fi
                done
            done
        fi
    fi

    # GPIO via /dev/gpiochip* (modern interface)
    if check_tool gpioinfo; then
        for chip in /dev/gpiochip*; do
            run gpioinfo "$chip" > "$WORKDIR/gpio/gpioinfo_$(basename $chip).txt"
        done
    fi

    state_mark gpio_complete
}

# ---------------- ACPI (NUCLEAR) ----------------
phase_acpi_nuclear() {
    state_done acpi_nuclear && return
    log "${YELLOW}Complete ACPI table extraction + decompilation...${NC}"

    # Binary dumps from sysfs
    if [ -d /sys/firmware/acpi/tables ]; then
        for table in /sys/firmware/acpi/tables/*; do
            [ -f "$table" ] && run sudo cp "$table" "$WORKDIR/acpi/$(basename "$table").bin"
        done

        # Dynamic tables
        if [ -d /sys/firmware/acpi/tables/dynamic ]; then
            run sudo cp -r /sys/firmware/acpi/tables/dynamic "$WORKDIR/acpi/dynamic_tables"
        fi
    fi

    # acpidump with all options
    check_tool acpidump && {
        run sudo acpidump -b -z -o "$WORKDIR/acpi/acpidump_all.dat"
        run sudo acpidump -s -o "$WORKDIR/acpi/acpidump_summary.txt"
    }

    # Decompile ALL tables
    if check_tool iasl; then
        for aml in "$WORKDIR/acpi"/*.bin "$WORKDIR/acpi"/*.dat; do
            [ -f "$aml" ] || continue
            basename_file=$(basename "$aml" | sed 's/\.[^.]*$//')
            run iasl -d "$aml" -p "$WORKDIR/acpi/${basename_file}" 2>&1 | tee "$WORKDIR/acpi/${basename_file}_iasl.log"
        done

        # Extract specific tables
        run iasl -e "$WORKDIR/acpi"/*.aml -d "$WORKDIR/acpi"/DSDT*.* 2>/dev/null || true
    fi

    # EC methods extraction
    grep -Ehi "_PTS|_WAK|_S[0-9]|_GPE|_Q[0-9A-F]{2}|_REG|_L[0-9A-F]{2}|_E[0-9A-F]{2}" "$WORKDIR/acpi"/*.dsl 2>/dev/null > "$WORKDIR/acpi/ec_gpe_methods.txt" || true

    # Power management methods
    grep -Ehi "_ON_|_OFF|_PS[0-3]|_PR[0-3]|_TMP|_CRT|_HOT|_PSV|_TC[12]|_TSP|_AC[0-9]|_AL[0-9]" "$WORKDIR/acpi"/*.dsl 2>/dev/null > "$WORKDIR/acpi/power_thermal_methods.txt" || true

    # Device definitions
    grep -Ehi "Device \(|Name \(_HID|Name \(_ADR|Name \(_CID" "$WORKDIR/acpi"/*.dsl 2>/dev/null > "$WORKDIR/acpi/device_definitions.txt" || true

    state_mark acpi_nuclear
}
phase_ec_nuclear() {
    state_done ec_nuclear && return
    log "${YELLOW}Complete EC/SuperIO extraction...${NC}"

    # SuperIO verbose detection
    if [ -f "$UTILDIR/superiotool/superiotool" ]; then
        run sudo "$UTILDIR/superiotool/superiotool" -deV > "$WORKDIR/ec/superio_registers_full.txt"
        run sudo "$UTILDIR/superiotool/superiotool" -d > "$WORKDIR/ec/superio_dump.txt"
    fi

    # EC commands (coreboot ectool)
    if command -v ectool &>/dev/null; then
        run sudo ectool chipinfo > "$WORKDIR/ec/ec_chipinfo.txt" 2>/dev/null || true
        run sudo ectool version > "$WORKDIR/ec/ec_version.txt" 2>/dev/null || true
        run sudo ectool fwversion > "$WORKDIR/ec/ec_fw_version.txt" 2>/dev/null || true
        run sudo ectool temps all > "$WORKDIR/ec/ec_temps.txt" 2>/dev/null || true
        run sudo ectool thermalget > "$WORKDIR/ec/ec_thermal_policy.txt" 2>/dev/null || true
        run sudo ectool pwmgetfanrpm all > "$WORKDIR/ec/ec_fan_rpm.txt" 2>/dev/null || true
        run sudo ectool pwmgetduty > "$WORKDIR/ec/ec_pwm_duty.txt" 2>/dev/null || true
        run sudo ectool battery > "$WORKDIR/ec/ec_battery.txt" 2>/dev/null || true
        run sudo ectool usbpd > "$WORKDIR/ec/ec_usbpd.txt" 2>/dev/null || true
        run sudo ectool gpioget > "$WORKDIR/ec/ec_gpio.txt" 2>/dev/null || true

        # EC RAM complete dump (0x00-0xFF)
        info "Dumping EC RAM (256 bytes)..."
        for addr in $(seq 0 255); do
            printf "0x%02X: " "$addr" >> "$WORKDIR/ec/ec_ram_full.txt"
            sudo ectool ecread "$addr" 2>/dev/null >> "$WORKDIR/ec/ec_ram_full.txt" || echo "N/A" >> "$WORKDIR/ec/ec_ram_full.txt"
        done

        # EC RAM hexdump format
        {
            echo "EC RAM Hexdump:"
            for addr in $(seq 0 16 240); do
                printf "%02X: " "$addr"
                for offset in $(seq 0 15); do
                    val=$(sudo ectool ecread $((addr + offset)) 2>/dev/null || echo "XX")
                    printf "%02s " "$val"
                done
                echo
            done
        } > "$WORKDIR/ec/ec_ram_hexdump.txt"
    fi

    # EC ports 0x60/0x64 status
    if check_tool inb; then
        for port in 0x60 0x64 0x62 0x66; do
            printf "Port 0x%02X: " "$port" >> "$WORKDIR/ec/ec_ports.txt"
            sudo inb "$port" 2>/dev/null >> "$WORKDIR/ec/ec_ports.txt" || echo "N/A" >> "$WORKDIR/ec/ec_ports.txt"
        done
    fi

    # EC firmware extraction attempt (device-specific)
    info "Attempting EC firmware extraction..."
    if [ -r /sys/kernel/debug/ec ]; then
        run sudo cat /sys/kernel/debug/ec/ec0/io > "$WORKDIR/ec/ec_debug_io.txt" 2>/dev/null || true
    fi

    state_mark ec_nuclear
}

# ---------------- UEFI VARIABLES (COMPLETE) ----------------
phase_uefi_complete() {
    state_done uefi_complete && return
    log "${YELLOW}Complete UEFI variable extraction...${NC}"

    if [ -d /sys/firmware/efi/efivars ]; then
        # Full backup
        run sudo tar czf "$WORKDIR/uefi/efivars_complete.tar.gz" /sys/firmware/efi/efivars/

        # Individual variables with metadata
        for var in /sys/firmware/efi/efivars/*; do
            varname=$(basename "$var")
            {
                echo "=== $varname ==="
                sudo hexdump -C "$var" 2>/dev/null
                echo "Size: $(stat -c%s "$var" 2>/dev/null)"
                echo "Modified: $(stat -c%y "$var" 2>/dev/null)"
            } > "$WORKDIR/uefi/${varname}.hex"
        done

        # Parse specific variables
        for key in "BootOrder" "Boot[0-9A-F]*" "DriverOrder" "Driver[0-9A-F]*" "SetupMode" "SecureBoot" "PK" "KEK" "db" "dbx"; do
            if ls /sys/firmware/efi/efivars/${key}-* 2>/dev/null; then
                run sudo cp /sys/firmware/efi/efivars/${key}-* "$WORKDIR/uefi/"
            fi
        done

        # Boot configuration
        run efibootmgr -v > "$WORKDIR/uefi/boot_config_verbose.txt"
        run efibootmgr --unicode > "$WORKDIR/uefi/boot_config_unicode.txt"
    else
        warn "Not in UEFI mode or efivars not accessible"
    fi

    # EFI System Partition complete backup
    esp=$(findmnt -n -o TARGET /boot/efi 2>/dev/null || findmnt -n -o TARGET /efi 2>/dev/null)
    if [ -n "$esp" ]; then
        info "Backing up ESP: $esp"
        run sudo rsync -av --progress "$esp/" "$WORKDIR/bootloader/esp_complete/"

        # Extract all EFI binaries
        find "$esp" -name "*.efi" -exec cp {} "$WORKDIR/firmware_blobs/" \; 2>/dev/null || true
    fi

    # UEFI firmware tables
    if [ -d /sys/firmware/efi/systab ]; then
        run sudo cat /sys/firmware/efi/systab > "$WORKDIR/uefi/systab.txt"
    fi

    # ESRT (EFI System Resource Table) - firmware update info
    if [ -d /sys/firmware/efi/esrt ]; then
        for entry in /sys/firmware/efi/esrt/entries/*; do
            [ -d "$entry" ] || continue
            {
                echo "=== $(basename $entry) ==="
                cat "$entry"/* 2>/dev/null
            } >> "$WORKDIR/uefi/esrt_entries.txt"
        done
    fi

    state_mark uefi_complete
}

# ---------------- SECURE BOOT (COMPLETE) ----------------
phase_secure_boot_complete() {
    state_done secure_boot_complete && return
    log "${YELLOW}Complete Secure Boot key extraction...${NC}"

    check_tool mokutil && {
        run mokutil --sb-state > "$WORKDIR/secure_boot/sb_state.txt"
        run mokutil --list-enrolled > "$WORKDIR/secure_boot/mok_enrolled_verbose.txt"
        run mokutil --list-enrolled --ca > "$WORKDIR/secure_boot/mok_ca.txt"
        run mokutil --list-new > "$WORKDIR/secure_boot/mok_pending.txt"
        run mokutil --list-delete > "$WORKDIR/secure_boot/mok_delete_pending.txt"
        run mokutil --export > "$WORKDIR/secure_boot/mok_export.txt" 2>/dev/null || true
    }

    # Extract keys from efivars
    for key in PK KEK db dbx; do
        keyfiles=$(find /sys/firmware/efi/efivars/ -name "${key}-*" 2>/dev/null)
        for keyfile in $keyfiles; do
            [ -f "$keyfile" ] && run sudo cp "$keyfile" "$WORKDIR/secure_boot/$(basename $keyfile)"
        done
    done

    # Secure Boot status from multiple sources
    if [ -f /sys/firmware/efi/efivars/SecureBoot-* ]; then
        run sudo hexdump -C /sys/firmware/efi/efivars/SecureBoot-* > "$WORKDIR/secure_boot/secureboot_status.txt"
    fi

    if [ -f /sys/firmware/efi/efivars/SetupMode-* ]; then
        run sudo hexdump -C /sys/firmware/efi/efivars/SetupMode-* > "$WORKDIR/secure_boot/setup_mode.txt"
    fi

    # Extract certificates from ESP
    find "$WORKDIR/bootloader/esp_complete" -name "*.cer" -o -name "*.crt" -o -name "*.der" | while read cert; do
        run cp "$cert" "$WORKDIR/secure_boot/"
    done

    state_mark secure_boot_complete
}

# ---------------- BOOT GUARD / SECURITY FEATURES ----------------
phase_security_features() {
    state_done security_features && return
    log "${YELLOW}Analyzing security features (Boot Guard, TXT, SGX)...${NC}"

    # Intel Boot Guard
    if check_tool chipsec_main; then
        safe_run sudo chipsec_main -m common.bios_wp > "$WORKDIR/boot_guard/chipsec_bios_wp.txt"
        safe_run sudo chipsec_main -m common.bios_smi > "$WORKDIR/boot_guard/chipsec_bios_smi.txt"
        safe_run sudo chipsec_main -m common.secureboot.variables > "$WORKDIR/boot_guard/chipsec_sb_vars.txt"
    fi

    # TXT (Trusted Execution Technology)
    if [ -d /sys/kernel/debug/txt ]; then
        run sudo cat /sys/kernel/debug/txt/version > "$WORKDIR/security/txt_version.txt" 2>/dev/null || true
        run sudo cat /sys/kernel/debug/txt/status > "$WORKDIR/security/txt_status.txt" 2>/dev/null || true
    fi

    # SGX (Software Guard Extensions)
    if grep -q sgx /proc/cpuinfo; then
        info "SGX detected in CPU"
        echo "SGX present" > "$WORKDIR/sgx/sgx_detected.txt"

        if [ -d /dev/sgx ]; then
            run ls -la /dev/sgx* > "$WORKDIR/sgx/sgx_devices.txt"
        fi

        if check_tool cpuid; then
            run cpuid -1 | grep -i sgx > "$WORKDIR/sgx/cpuid_sgx.txt"
        fi
    fi

    # PAVP (Protected Audio Video Path)
    if lspci | grep -i "Audio"; then
        run lspci -vvv | grep -A20 -i audio > "$WORKDIR/security/audio_caps.txt"
    fi

    # Thunderbolt security levels
    if [ -d /sys/bus/thunderbolt/devices ]; then
        for tb in /sys/bus/thunderbolt/devices/*; do
            [ -d "$tb" ] || continue
            {
                echo "=== $(basename $tb) ==="
                cat "$tb/security" 2>/dev/null
                cat "$tb/authorized" 2>/dev/null
                cat "$tb/device_name" 2>/dev/null
            } >> "$WORKDIR/security/thunderbolt_security.txt"
        done
    fi

    state_mark security_features
}

# ---------------- TPM (COMPLETE) ----------------
phase_tpm_complete() {
    state_done tpm_complete && return
    log "${YELLOW}Complete TPM extraction...${NC}"

    if [ -c /dev/tpm0 ]; then
        # TPM 1.2
        if check_tool tpm_version; then
            run tpm_version > "$WORKDIR/tpm/tpm_version.txt"
            run tpm_getcap > "$WORKDIR/tpm/tpm_capabilities.txt" 2>/dev/null || true
        fi

        # TPM 2.0
        if check_tool tpm2_getcap; then
            run tpm2_getcap properties-fixed > "$WORKDIR/tpm/tpm2_properties_fixed.txt"
            run tpm2_getcap properties-variable > "$WORKDIR/tpm/tpm2_properties_variable.txt"
            run tpm2_getcap pcrs > "$WORKDIR/tpm/tpm2_pcrs.txt"
            run tpm2_getcap algorithms > "$WORKDIR/tpm/tpm2_algorithms.txt"
            run tpm2_getcap commands > "$WORKDIR/tpm/tpm2_commands.txt"
            run tpm2_getcap handles-persistent > "$WORKDIR/tpm/tpm2_handles_persistent.txt"
            run tpm2_getcap handles-transient > "$WORKDIR/tpm/tpm2_handles_transient.txt"

            # PCR values
            for pcr in $(seq 0 23); do
                run tpm2_pcrread "sha256:$pcr" >> "$WORKDIR/tpm/tpm2_pcr_values.txt" 2>/dev/null || true
            done

            # Event log
            if [ -r /sys/kernel/security/tpm0/binary_bios_measurements ]; then
                run sudo cp /sys/kernel/security/tpm0/binary_bios_measurements "$WORKDIR/tpm/tpm_event_log.bin"
                check_tool tpm2_eventlog && run tpm2_eventlog "$WORKDIR/tpm/tpm_event_log.bin" > "$WORKDIR/tpm/tpm_event_log_parsed.txt"
            fi
        fi
    else
        warn "No TPM device found"
    fi

    state_mark tpm_complete
}

# ---------------- VIDEO / VBT / GOP (COMPLETE) ----------------
phase_video_complete() {
    state_done video_complete && return
    log "${YELLOW}Complete video BIOS extraction...${NC}"

    # Intel VBT
    if [ -f "$UTILDIR/intelvbttool/intelvbttool" ] && [ -f "$WORKDIR/spi/firmware_full.bin" ]; then
        run "$UTILDIR/intelvbttool/intelvbttool" "$WORKDIR/spi/firmware_full.bin" -e "$WORKDIR/vbt/vbt_extracted.bin"
        run "$UTILDIR/intelvbttool/intelvbttool" "$WORKDIR/vbt/vbt_extracted.bin" -d > "$WORKDIR/vbt/vbt_decoded_full.txt"
    fi

    # Kernel VBT
    if [ -f /sys/kernel/debug/dri/0/i915_vbt ]; then
        run sudo cp /sys/kernel/debug/dri/0/i915_vbt "$WORKDIR/vbt/i915_vbt_kernel.bin"
    fi

    # Display info from i915
    if [ -d /sys/kernel/debug/dri/0 ]; then
        for file in /sys/kernel/debug/dri/0/i915_*; do
            [ -f "$file" ] && run sudo cat "$file" > "$WORKDIR/video/i915_$(basename $file).txt" 2>/dev/null || true
        done
    fi

    # EDID dumps from all displays
    for card in /sys/class/drm/card*/card*-*/edid; do
        [ -f "$card" ] || continue
        connector=$(echo "$card" | grep -oP 'card\d+-[^/]+')
        run sudo cp "$card" "$WORKDIR/video/edid_${connector}.bin" 2>/dev/null || true
        check_tool edid-decode && run edid-decode < "$card" > "$WORKDIR/video/edid_${connector}_decoded.txt" 2>/dev/null || true
    done

    # Option ROMs from all PCI devices
    for dev in /sys/bus/pci/devices/*; do
        rom="$dev/rom"
        [ -f "$rom" ] || continue

        bdf=$(basename "$dev")
        vendor=$(cat "$dev/vendor" 2>/dev/null)
        device=$(cat "$dev/device" 2>/dev/null)

        # Enable ROM BAR
        echo 1 | sudo tee "$rom" >/dev/null 2>&1

        # Check if ROM is actually present
        if [ "$(stat -c%s "$rom" 2>/dev/null)" -gt 0 ]; then
            info "Extracting Option ROM from $bdf ($vendor:$device)"
            run sudo dd if="$rom" of="$WORKDIR/video/optionrom_${bdf}_${vendor}_${device}.bin" bs=64k 2>/dev/null
        fi

        # Disable ROM BAR
        echo 0 | sudo tee "$rom" >/dev/null 2>&1
    done

    # GOP (UEFI Graphics Output Protocol) drivers from ESP
    find "$WORKDIR/bootloader/esp_complete" -iname "*gop*.efi" -exec cp {} "$WORKDIR/video/" \; 2>/dev/null || true

    state_mark video_complete
}

# ---------------- CBFS / CBMEM (COMPLETE) ----------------
phase_cbfs_complete() {
    state_done cbfs_complete && return
    log "${YELLOW}Complete CBFS/CBMEM extraction...${NC}"

    if [ -f "$WORKDIR/spi/firmware_full.bin" ] && [ -f "$UTILDIR/cbfstool/cbfstool" ]; then
        # List all entries
        run "$UTILDIR/cbfstool/cbfstool" "$WORKDIR/spi/firmware_full.bin" print -v > "$WORKDIR/cbfs/cbfstool_list_verbose.txt"
        run "$UTILDIR/cbfstool/cbfstool" "$WORKDIR/spi/firmware_full.bin" layout > "$WORKDIR/cbfs/cbfstool_layout.txt"

        # Extract ALL entries
        mkdir -p "$WORKDIR/cbfs/extracted"
        info "Extracting all CBFS entries..."

        # Parse list and extract each file
        "$UTILDIR/cbfstool/cbfstool" "$WORKDIR/spi/firmware_full.bin" print | tail -n +4 | while read -r line; do
            # Extract filename (first field)
            fname=$(echo "$line" | awk '{print $1}')
            [ -z "$fname" ] && continue

            info "Extracting: $fname"
            "$UTILDIR/cbfstool/cbfstool" "$WORKDIR/spi/firmware_full.bin" extract -n "$fname" -f "$WORKDIR/cbfs/extracted/${fname}" 2>/dev/null || warn "Failed to extract $fname"
        done

        # Extract specific known entries by type
        for type in "raw" "stage" "payload" "optionrom" "bootblock" "fsp" "mrc" "microcode" "refcode"; do
            run "$UTILDIR/cbfstool/cbfstool" "$WORKDIR/spi/firmware_full.bin" print -k "$type" > "$WORKDIR/cbfs/cbfs_type_${type}.txt" 2>/dev/null || true
        done
    fi

    # Runtime CBMEM
    if [ -f "$UTILDIR/cbmem/cbmem" ]; then
        run sudo "$UTILDIR/cbmem/cbmem" -c > "$WORKDIR/cbfs/cbmem_console.txt"
        run sudo "$UTILDIR/cbmem/cbmem" -t > "$WORKDIR/cbfs/cbmem_timestamps.txt"
        run sudo "$UTILDIR/cbmem/cbmem" -l > "$WORKDIR/cbfs/cbmem_list.txt"
        run sudo "$UTILDIR/cbmem/cbmem" -1 > "$WORKDIR/cbfs/cbmem_oneshot.txt"
        run sudo "$UTILDIR/cbmem/cbmem" -a > "$WORKDIR/cbfs/cbmem_all.txt"
    fi

    # SMM store (if present)
    if [ -f "$UTILDIR/smmstoretool/smmstoretool" ]; then
        run "$UTILDIR/smmstoretool/smmstoretool" "$WORKDIR/spi/firmware_full.bin" dump > "$WORKDIR/cbfs/smmstore_dump.txt" 2>/dev/null || true
    fi

    state_mark cbfs_complete
}

# ---------------- MICROCODE EXTRACTION ----------------
phase_microcode() {
    state_done microcode && return
    log "${YELLOW}Extracting microcode updates...${NC}"

    # From CBFS
    if [ -d "$WORKDIR/cbfs/extracted" ]; then
        find "$WORKDIR/cbfs/extracted" -name "*ucode*" -o -name "*microcode*" | while read ucode; do
            run cp "$ucode" "$WORKDIR/microcode/$(basename $ucode)"
        done
    fi

    # From kernel
    if [ -d /lib/firmware/intel-ucode ]; then
        run sudo cp -r /lib/firmware/intel-ucode "$WORKDIR/microcode/kernel_intel_ucode"
    fi

    if [ -d /lib/firmware/amd-ucode ]; then
        run sudo cp -r /lib/firmware/amd-ucode "$WORKDIR/microcode/kernel_amd_ucode"
    fi

    # Current loaded microcode
    run grep microcode /proc/cpuinfo | sort -u > "$WORKDIR/microcode/loaded_version.txt"

    # MSR microcode revision
    check_tool rdmsr && run sudo rdmsr -a 0x8B > "$WORKDIR/microcode/msr_microcode_rev.txt"

    state_mark microcode
}

# ---------------- STORAGE FIRMWARE (COMPLETE) ----------------
phase_storage_complete() {
    state_done storage_complete && return
    log "${YELLOW}Complete storage firmware extraction...${NC}"

    # NVMe drives
    for nvme in /dev/nvme*n1; do
        [ -b "$nvme" ] || continue
        nvme_id=$(echo "$nvme" | sed 's/\/dev\///')

        info "Extracting NVMe data: $nvme_id"
        check_tool nvme && {
            run sudo nvme id-ctrl "$nvme" -o json > "$WORKDIR/storage/${nvme_id}_id_ctrl.json"
            run sudo nvme id-ctrl "$nvme" -H > "$WORKDIR/storage/${nvme_id}_id_ctrl_human.txt"
            run sudo nvme id-ns "$nvme" -o json > "$WORKDIR/storage/${nvme_id}_id_ns.json"
            run sudo nvme fw-log "$nvme" > "$WORKDIR/storage/${nvme_id}_fw_log.txt"
            run sudo nvme smart-log "$nvme" > "$WORKDIR/storage/${nvme_id}_smart.txt"
            run sudo nvme error-log "$nvme" > "$WORKDIR/storage/${nvme_id}_error_log.txt"
            run sudo nvme get-log "$nvme" -i 0x01 > "$WORKDIR/storage/${nvme_id}_error_info.txt" 2>/dev/null || true
            run sudo nvme get-log "$nvme" -i 0x02 > "$WORKDIR/storage/${nvme_id}_smart_log.txt" 2>/dev/null || true
            run sudo nvme get-feature "$nvme" -f 0x07 > "$WORKDIR/storage/${nvme_id}_num_queues.txt" 2>/dev/null || true
        }
    done

    # SATA/SAS drives
    for disk in /dev/sd?; do
        [ -b "$disk" ] || continue
        disk_id=$(basename "$disk")

        info "Extracting SATA/SAS data: $disk_id"
        check_tool hdparm && {
            run sudo hdparm -I "$disk" > "$WORKDIR/storage/${disk_id}_identify.txt"
            run sudo hdparm -i "$disk" > "$WORKDIR/storage/${disk_id}_info.txt"
            run sudo hdparm --security-help "$disk" > "$WORKDIR/storage/${disk_id}_security.txt" 2>/dev/null || true
        }

        check_tool smartctl && {
            run sudo smartctl -a "$disk" > "$WORKDIR/storage/${disk_id}_smart_full.txt"
            run sudo smartctl -x "$disk" > "$WORKDIR/storage/${disk_id}_smart_extended.txt"
            run sudo smartctl -l error "$disk" > "$WORKDIR/storage/${disk_id}_error_log.txt"
            run sudo smartctl -l selftest "$disk" > "$WORKDIR/storage/${disk_id}_selftest.txt"
            run sudo smartctl -c "$disk" > "$WORKDIR/storage/${disk_id}_capabilities.txt"
        }
    done

    # RAID controllers
    if check_tool storcli64; then
        run sudo storcli64 /call show all > "$WORKDIR/storage/raid_controller_full.txt" 2>/dev/null || true
    fi

    state_mark storage_complete
}

# ---------------- NETWORK FIRMWARE (COMPLETE) ----------------
phase_network_complete() {
    state_done network_complete && return
    log "${YELLOW}Complete network firmware extraction...${NC}"

    for netdev in /sys/class/net/*; do
        iface=$(basename "$netdev")
        [ "$iface" == "lo" ] && continue

        info "Extracting network data: $iface"

        check_tool ethtool && {
            run sudo ethtool -i "$iface" > "$WORKDIR/network/${iface}_driver_info.txt"
            run sudo ethtool "$iface" > "$WORKDIR/network/${iface}_settings.txt"
            run sudo ethtool -k "$iface" > "$WORKDIR/network/${iface}_features.txt"
            run sudo ethtool -S "$iface" > "$WORKDIR/network/${iface}_statistics.txt"
            run sudo ethtool -g "$iface" > "$WORKDIR/network/${iface}_ring_params.txt"
            run sudo ethtool -c "$iface" > "$WORKDIR/network/${iface}_coalesce.txt"

            # EEPROM dump
            run sudo ethtool -e "$iface" raw on > "$WORKDIR/network/${iface}_eeprom.bin" 2>/dev/null || warn "$iface EEPROM dump failed"

            # Firmware version
            run sudo ethtool -m "$iface" > "$WORKDIR/network/${iface}_module_info.txt" 2>/dev/null || true
        }

        # MAC address
        if [ -f "$netdev/address" ]; then
            run cat "$netdev/address" > "$WORKDIR/network/${iface}_mac.txt"
        fi

        # Link state
        if [ -f "$netdev/operstate" ]; then
            run cat "$netdev/operstate" > "$WORKDIR/network/${iface}_state.txt"
        fi
    done

    # Wireless info
    if check_tool iw; then
        for wdev in $(iw dev | grep Interface | awk '{print $2}'); do
            run sudo iw "$wdev" info > "$WORKDIR/network/${wdev}_wireless_info.txt"
            run sudo iw "$wdev" scan > "$WORKDIR/network/${wdev}_scan.txt" 2>/dev/null || true
        done
    fi

    state_mark network_complete
}

# ---------------- USB DEVICE FIRMWARE (COMPLETE) ----------------
phase_usb_complete() {
    state_done usb_complete && return
    log "${YELLOW}Complete USB device enumeration...${NC}"

    run lsusb -vvv -t > "$WORKDIR/usb/usb_tree_verbose.txt"

    # Per-device descriptors and firmware
    for usbdev in /sys/bus/usb/devices/*; do
        [ -d "$usbdev" ] || continue
        devid=$(basename "$usbdev")

        # Descriptors
        if [ -f "$usbdev/descriptors" ]; then
            run sudo cp "$usbdev/descriptors" "$WORKDIR/usb/${devid}_descriptors.bin"
        fi

        # Manufacturer/product info
        {
            [ -f "$usbdev/manufacturer" ] && echo "Manufacturer: $(cat $usbdev/manufacturer)"
            [ -f "$usbdev/product" ] && echo "Product: $(cat $usbdev/product)"
            [ -f "$usbdev/serial" ] && echo "Serial: $(cat $usbdev/serial)"
            [ -f "$usbdev/version" ] && echo "Version: $(cat $usbdev/version)"
            [ -f "$usbdev/bcdDevice" ] && echo "bcdDevice: $(cat $usbdev/bcdDevice)"
        } > "$WORKDIR/usb/${devid}_info.txt" 2>/dev/null
    done

    # USB controller details
    run lspci -vvv | grep -A30 "USB controller" > "$WORKDIR/usb/usb_controllers.txt"

    state_mark usb_complete
}

# ---------------- THUNDERBOLT NVM ----------------
phase_thunderbolt() {
    state_done thunderbolt && return
    log "${YELLOW}Extracting Thunderbolt NVM...${NC}"

    if [ -d /sys/bus/thunderbolt/devices ]; then
        for tb in /sys/bus/thunderbolt/devices/*; do
            [ -d "$tb" ] || continue
            tbid=$(basename "$tb")

            {
                echo "=== Thunderbolt Device: $tbid ==="
                [ -f "$tb/device_name" ] && echo "Device: $(cat $tb/device_name)"
                [ -f "$tb/vendor_name" ] && echo "Vendor: $(cat $tb/vendor_name)"
                [ -f "$tb/unique_id" ] && echo "UUID: $(cat $tb/unique_id)"
                [ -f "$tb/authorized" ] && echo "Authorized: $(cat $tb/authorized)"
                [ -f "$tb/security" ] && echo "Security: $(cat $tb/security)"
                [ -f "$tb/nvm_version" ] && echo "NVM Version: $(cat $tb/nvm_version)"
            } >> "$WORKDIR/thunderbolt/thunderbolt_devices.txt"

            # NVM firmware (if readable)
            if [ -f "$tb/nvm_authenticate" ]; then
                run sudo cat "$tb/nvm_authenticate" > "$WORKDIR/thunderbolt/${tbid}_nvm_status.txt" 2>/dev/null || true
            fi
        done
    else
        warn "No Thunderbolt devices found"
    fi

    state_mark thunderbolt
}

# ---------------- AUDIO FIRMWARE ----------------
phase_audio() {
    state_done audio && return
    log "${YELLOW}Extracting audio firmware...${NC}"

    # Audio devices
    run cat /proc/asound/cards > "$WORKDIR/audio/asound_cards.txt"
    run cat /proc/asound/devices > "$WORKDIR/audio/asound_devices.txt"
    run cat /proc/asound/version > "$WORKDIR/audio/asound_version.txt"

    # Codec info for each card
    for card in /proc/asound/card*; do
        [ -d "$card" ] || continue
        cardid=$(basename "$card")

        if [ -f "$card/codec#0" ]; then
            run cat "$card/codec#0" > "$WORKDIR/audio/${cardid}_codec0.txt"
        fi

        if [ -d "$card/pcm0p" ]; then
            run cat "$card/pcm0p/info" > "$WORKDIR/audio/${cardid}_pcm_info.txt" 2>/dev/null || true
        fi
    done

    # HDA codec firmware
    for codec in /sys/class/sound/hwC*D*/; do
        [ -d "$codec" ] || continue
        codecid=$(basename "$codec")

        {
            [ -f "$codec/vendor_id" ] && echo "Vendor: $(cat $codec/vendor_id)"
            [ -f "$codec/subsystem_id" ] && echo "Subsystem: $(cat $codec/subsystem_id)"
            [ -f "$codec/chip_name" ] && echo "Chip: $(cat $codec/chip_name)"
        } > "$WORKDIR/audio/${codecid}_info.txt" 2>/dev/null
    done

    # Loaded firmware
    grep -r "snd" /sys/module/*/parameters/ 2>/dev/null > "$WORKDIR/audio/snd_module_params.txt" || true

    state_mark audio
}

# ---------------- SENSORS ----------------
phase_sensors() {
    state_done sensors && return
    log "${YELLOW}Reading all sensors...${NC}"

    check_tool sensors && {
        run sensors -A > "$WORKDIR/sensors/sensors_all.txt"
        run sensors -u > "$WORKDIR/sensors/sensors_raw.txt"
    }

    # Thermal zones
    if [ -d /sys/class/thermal ]; then
        for zone in /sys/class/thermal/thermal_zone*; do
            zoneid=$(basename "$zone")
            {
                echo "=== $zoneid ==="
                cat "$zone/type" 2>/dev/null
                cat "$zone/temp" 2>/dev/null
                cat "$zone/mode" 2>/dev/null
            } >> "$WORKDIR/sensors/thermal_zones.txt"
        done
    fi

    # Hwmon devices
    if [ -d /sys/class/hwmon ]; then
        for hwmon in /sys/class/hwmon/hwmon*; do
            hwmonid=$(basename "$hwmon")
            {
                echo "=== $hwmonid ==="
                cat "$hwmon/name" 2>/dev/null
                find "$hwmon" -name "temp*_input" -exec sh -c 'echo "$1: $(cat $1)"' _ {} \; 2>/dev/null
                find "$hwmon" -name "fan*_input" -exec sh -c 'echo "$1: $(cat $1)"' _ {} \; 2>/dev/null
            } >> "$WORKDIR/sensors/hwmon_devices.txt"
        done
    fi

    state_mark sensors
}

# ---------------- KERNEL LOADED FIRMWARE ----------------
phase_firmware_blobs() {
    state_done firmware_blobs && return
    log "${YELLOW}Cataloging loaded firmware blobs...${NC}"

    # From /lib/firmware
    if [ -d /lib/firmware ]; then
        run find /lib/firmware -type f > "$WORKDIR/firmware_blobs/firmware_list.txt"
        run du -sh /lib/firmware/* > "$WORKDIR/firmware_blobs/firmware_sizes.txt"
    fi

    # Currently loaded
    run dmesg | grep -i "firmware" > "$WORKDIR/firmware_blobs/dmesg_firmware.txt"

    # From debugfs
    if [ -d /sys/kernel/debug/firmware ]; then
        run sudo ls -laR /sys/kernel/debug/firmware > "$WORKDIR/firmware_blobs/debugfs_firmware.txt"
    fi

    state_mark firmware_blobs
}

# ---------------- DMA / IOMMU ----------------
phase_dma_iommu() {
    state_done dma_iommu && return
    log "${YELLOW}Extracting DMA/IOMMU configuration...${NC}"

    # IOMMU groups
    if [ -d /sys/kernel/iommu_groups ]; then
        for group in /sys/kernel/iommu_groups/*; do
            groupid=$(basename "$group")
            echo "=== IOMMU Group $groupid ===" >> "$WORKDIR/dma/iommu_groups.txt"
            ls -l "$group/devices" >> "$WORKDIR/dma/iommu_groups.txt"
        done
    fi

    # DMA remapping
    run dmesg | grep -i "dmar\|iommu" > "$WORKDIR/dma/dmesg_dmar_iommu.txt"

    # Kernel IOMMU status
    run cat /proc/cmdline | grep -o "intel_iommu=[^ ]*" > "$WORKDIR/dma/iommu_cmdline.txt" || echo "Not set" > "$WORKDIR/dma/iommu_cmdline.txt"

    state_mark dma_iommu
}

# ---------------- CLOCK / VRM / POWER ----------------
phase_power_clocks() {
    state_done power_clocks && return
    log "${YELLOW}Extracting power/clock configuration...${NC}"

    # CPU frequency info
    if [ -d /sys/devices/system/cpu/cpufreq ]; then
        run cat /sys/devices/system/cpu/cpu*/cpufreq/* > "$WORKDIR/clock/cpufreq_all.txt" 2>/dev/null || true
    fi

    # Clock sources
    run cat /sys/devices/system/clocksource/clocksource0/available_clocksource > "$WORKDIR/clock/available_clocksources.txt"
    run cat /sys/devices/system/clocksource/clocksource0/current_clocksource > "$WORKDIR/clock/current_clocksource.txt"

    # RAPL (Running Average Power Limit)
    if [ -d /sys/class/powercap ]; then
        for rapl in /sys/class/powercap/intel-rapl:*; do
            [ -d "$rapl" ] || continue
            raplid=$(basename "$rapl")
            {
                echo "=== $raplid ==="
                cat "$rapl/name" 2>/dev/null
                cat "$rapl/energy_uj" 2>/dev/null
                cat "$rapl/max_energy_range_uj" 2>/dev/null
            } >> "$WORKDIR/power/rapl_domains.txt"
        done
    fi

    # Battery (if laptop)
    if [ -d /sys/class/power_supply ]; then
        for ps in /sys/class/power_supply/*; do
            psid=$(basename "$ps")
            run cat "$ps/uevent" > "$WORKDIR/power/${psid}_uevent.txt" 2>/dev/null || true
        done
    fi

    # Voltage regulators
    if [ -d /sys/class/regulator ]; then
        for reg in /sys/class/regulator/regulator.*; do
            regid=$(basename "$reg")
            {
                echo "=== $regid ==="
                cat "$reg/name" 2>/dev/null
                cat "$reg/microvolts" 2>/dev/null
                cat "$reg/microamps" 2>/dev/null
            } >> "$WORKDIR/vrm/regulators.txt"
        done
    fi

    state_mark power_clocks
}

# ---------------- BOOTLOADER CONFIGS (COMPLETE) ----------------
phase_bootloader_complete() {
    state_done bootloader_complete && return
    log "${YELLOW}Complete bootloader configuration backup...${NC}"

    # GRUB
    if [ -d /boot/grub ]; then
        run sudo cp -r /boot/grub "$WORKDIR/bootloader/grub_backup"
        run sudo grub-mkconfig > "$WORKDIR/bootloader/grub_generated_config.txt" 2>&1
    fi

    # systemd-boot
    if [ -d /boot/loader ]; then
        run sudo cp -r /boot/loader "$WORKDIR/bootloader/systemd_boot_backup"
        run bootctl status > "$WORKDIR/bootloader/bootctl_status.txt" 2>/dev/null || true
        run bootctl list > "$WORKDIR/bootloader/bootctl_list.txt" 2>/dev/null || true
    fi

    # SYSLINUX/ISOLINUX
    for cfg in /boot/syslinux/syslinux.cfg /boot/isolinux/isolinux.cfg; do
        [ -f "$cfg" ] && run sudo cp "$cfg" "$WORKDIR/bootloader/$(basename $(dirname $cfg))_$(basename $cfg)"
    done

    # rEFInd
    if [ -d /boot/EFI/refind ]; then
        run sudo cp -r /boot/EFI/refind "$WORKDIR/bootloader/refind_backup"
    fi

    # Boot entries
    if check_tool efibootmgr; then
        run efibootmgr -v > "$WORKDIR/bootloader/efi_boot_entries.txt"
    fi

    state_mark bootloader_complete
}

# ---------------- NVRAM / CMOS (COMPLETE) ----------------
phase_nvram_complete() {
    state_done nvram_complete && return
    log "${YELLOW}Complete NVRAM/CMOS extraction...${NC}"

    # Coreboot nvramtool
    if [ -f "$UTILDIR/nvramtool/nvramtool" ]; then
        run sudo "$UTILDIR/nvramtool/nvramtool" -a > "$WORKDIR/nvram/nvramtool_all.txt"
        run sudo "$UTILDIR/nvramtool/nvramtool" -x > "$WORKDIR/nvram/nvramtool_hex.txt"
        run sudo "$UTILDIR/nvramtool/nvramtool" -C > "$WORKDIR/nvram/nvramtool_checksum.txt" 2>/dev/null || true
    fi

    # Direct CMOS dump (ports 0x70/0x71 - Standard CMOS)
    if check_tool outb && check_tool inb; then
        info "Dumping CMOS via I/O ports..."
        {
            for bank in 0 1; do
                echo "=== Bank $bank ==="
                for addr in $(seq 0 255); do
                    # Select address
                    sudo outb 0x70 $((addr | (bank << 7))) 2>/dev/null
                    # Read data
                    val=$(sudo inb 0x71 2>/dev/null || echo "XX")
                    printf "%02X: %s\n" "$addr" "$val"
                done
            done
        } > "$WORKDIR/nvram/cmos_raw_dump.txt"
    fi

    # RTC (Real Time Clock) registers
    if [ -r /dev/rtc0 ]; then
        check_tool hwclock && run sudo hwclock --verbose > "$WORKDIR/nvram/rtc_hwclock.txt"
        run sudo cat /sys/class/rtc/rtc0/date > "$WORKDIR/nvram/rtc_date.txt" 2>/dev/null || true
        run sudo cat /sys/class/rtc/rtc0/time > "$WORKDIR/nvram/rtc_time.txt" 2>/dev/null || true
    fi

    state_mark nvram_complete
}

# ---------------- PERIPHERAL ENUMERATION (COMPLETE) ----------------
phase_peripherals_complete() {
    state_done peripherals_complete && return
    log "${YELLOW}Complete peripheral enumeration...${NC}"

    # Input devices
    run cat /proc/bus/input/devices > "$WORKDIR/peripheral/input_devices_full.txt"

    # HID devices detail
    if [ -d /sys/class/hidraw ]; then
        for hid in /sys/class/hidraw/hidraw*; do
            hidid=$(basename "$hid")
            {
                echo "=== $hidid ==="
                cat "$hid/device/uevent" 2>/dev/null
            } >> "$WORKDIR/peripheral/hidraw_devices.txt"
        done
    fi

    # Bluetooth
    check_tool hciconfig && run sudo hciconfig -a > "$WORKDIR/peripheral/bluetooth_hciconfig.txt"
    check_tool bluetoothctl && run sudo bluetoothctl show > "$WORKDIR/peripheral/bluetooth_info.txt"

    # Serial ports
    if [ -d /sys/class/tty ]; then
        for tty in /sys/class/tty/ttyS* /sys/class/tty/ttyUSB*; do
            [ -e "$tty" ] || continue
            ttyid=$(basename "$tty")
            run cat "$tty/dev" > "$WORKDIR/peripheral/${ttyid}_dev.txt" 2>/dev/null || true
        done
    fi

    state_mark peripherals_complete
}

# ---------------- MEMORY DUMP (CAREFUL) ----------------
phase_memory_dump() {
    state_done memory_dump && return
    danger "Attempting physical memory dump (SLOW and RISKY)"

    [[ "$INVASIVE_MODE" != "1" ]] && { warn "Skipping memory dump (enable INVASIVE_MODE=1)"; state_mark memory_dump; return; }

    if [ -r /dev/mem ]; then
        info "Dumping accessible memory regions..."

        # Low 1MB (BIOS area)
        safe_run sudo dd if=/dev/mem of="$WORKDIR/memory/mem_00000000_00100000.bin" bs=1M count=1 skip=0 iflag=fullblock 2>/dev/null

        # SMM region (if not locked)
        safe_run sudo dd if=/dev/mem of="$WORKDIR/memory/mem_000A0000_000BFFFF.bin" bs=128k count=1 skip=$((0xA0000/131072)) iflag=fullblock 2>/dev/null

        # Extended BIOS area
        safe_run sudo dd if=/dev/mem of="$WORKDIR/memory/mem_000F0000_00100000.bin" bs=64k count=1 skip=$((0xF0000/65536)) iflag=fullblock 2>/dev/null
    else
        warn "/dev/mem not accessible (kernel lockdown?)"
    fi

    # Alternative: try /dev/crash or crash utility
    check_tool crash && warn "Consider using 'crash' utility for full memory dump"

    state_mark memory_dump
}

# ---------------- FINAL LOGS (ENHANCED) ----------------
phase_logs() {
    state_done logs && return
    log "${YELLOW}Generating checksums, manifest, and analysis report...${NC}"

    # File tree
    if check_tool tree; then
        run tree -a -L 4 "$WORKDIR" > "$WORKDIR/logs/tree.txt"
    else
        run find "$WORKDIR" -type f > "$WORKDIR/logs/file_list.txt"
    fi

    # SHA256 all artifacts
    info "Computing checksums (this may take time)..."
    run find "$WORKDIR" -type f -exec sha256sum {} \; > "$WORKDIR/logs/all_hashes_sha256.txt"
    run find "$WORKDIR" -type f -exec md5sum {} \; > "$WORKDIR/logs/all_hashes_md5.txt"

    # File type analysis
    run find "$WORKDIR" -type f -exec file {} \; > "$WORKDIR/logs/file_types.txt"

    # Summary report
    {
        echo "================================================================"
        echo "        FIRMWARE EXTRACTION SUMMARY REPORT"
        echo "================================================================"
        echo ""
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo ""
        echo "=== Statistics ==="
        echo "Total files: $(find "$WORKDIR" -type f | wc -l)"
        echo "Total directories: $(find "$WORKDIR" -type d | wc -l)"
        echo "Total size: $(du -sh "$WORKDIR" | cut -f1)"
        echo ""
        echo "=== Hardware Info ==="
        [ -f "$LOGDIR/dmidecode_bios.txt" ] && echo "BIOS: $(grep -m1 "Version:" "$LOGDIR/dmidecode_bios.txt" || echo "Unknown")"
        [ -f "$LOGDIR/dmidecode_board.txt" ] && echo "Board: $(grep -m1 "Product Name:" "$LOGDIR/dmidecode_board.txt" || echo "Unknown")"
        [ -f "$LOGDIR/lscpu.txt" ] && echo "CPU: $(grep -m1 "Model name:" "$LOGDIR/lscpu.txt" | cut -d: -f2 | xargs)"
        echo ""
        echo "=== Key Artifacts ==="
        [ -f "$WORKDIR/spi/firmware_full.bin" ] && echo "✓ Full SPI firmware: $(stat -c%s "$WORKDIR/spi/firmware_full.bin" 2>/dev/null) bytes"
        [ -f "$WORKDIR/spi/region_bios.bin" ] && echo "✓ BIOS region: $(stat -c%s "$WORKDIR/spi/region_bios.bin" 2>/dev/null) bytes"
        [ -f "$WORKDIR/spi/region_me.bin" ] && echo "✓ ME region: $(stat -c%s "$WORKDIR/spi/region_me.bin" 2>/dev/null) bytes"
        [ -d "$WORKDIR/cbfs/extracted" ] && echo "✓ CBFS entries extracted: $(ls "$WORKDIR/cbfs/extracted" 2>/dev/null | wc -l)"
        [ -f "$WORKDIR/uefi/efivars_complete.tar.gz" ] && echo "✓ UEFI variables backed up"
        [ -f "$WORKDIR/memory/dmidecode_raw.bin" ] && echo "✓ SMBIOS tables dumped"
        [ -f "$WORKDIR/acpi/acpidump_all.dat" ] && echo "✓ ACPI tables dumped"
        echo ""
        echo "=== Next Steps ==="
        echo "1. Review $WORKDIR/logs/summary.txt"
        echo "2. Validate SPI dumps with checksums"
        echo "3. Begin coreboot device tree creation"
        echo "4. Analyze ACPI for EC/GPIO mappings"
        echo "5. Extract VBT for display init"
    } > "$WORKDIR/logs/summary.txt"

    cat "$WORKDIR/logs/summary.txt"

    state_mark logs
}

# ============================================================
# MAIN EXECUTION
# ============================================================

log "${GREEN}=======================================${NC}"
log "${GREEN}  NUCLEAR FIRMWARE EXTRACTION STARTED${NC}"
log "${GREEN}=======================================${NC}"
log "Workdir: $WORKDIR"
log "Invasive mode: $INVASIVE_MODE"
log "Dry run: $DRY_RUN"

require_root

# Pre-flight
install_missing_tools
load_kernel_modules
ec_tool_cleanup

# Build phase
phase_build

# System enumeration
phase_sysinfo

# Flash/Firmware
phase_spi
phase_me_csme
phase_cbfs_complete
phase_microcode

# CPU/Platform
phase_cpu_deep
phase_chipset_pch
phase_memory_deep
phase_memory_dump

# Buses and I/O
phase_pci_complete
phase_gpio_complete
phase_i2c_scan

# Firmware tables
phase_acpi_nuclear
phase_uefi_complete
phase_nvram_complete

# Embedded controllers
phase_ec_nuclear

# Security
phase_smm_analysis
phase_secure_boot_complete
phase_security_features
phase_tpm_complete

# Peripherals
phase_video_complete
phase_storage_complete
phase_network_complete
phase_usb_complete
phase_thunderbolt
phase_audio
phase_sensors
phase_peripherals_complete

# System state
phase_firmware_blobs
phase_dma_iommu
phase_power_clocks
phase_bootloader_complete

# Finalize
phase_logs

log "${GREEN}=======================================${NC}"
log "${GREEN}     ALL EXTRACTION PHASES COMPLETE${NC}"
log "${GREEN}=======================================${NC}"
log "Total artifacts: $WORKDIR"
log "Summary report: $WORKDIR/logs/summary.txt"
