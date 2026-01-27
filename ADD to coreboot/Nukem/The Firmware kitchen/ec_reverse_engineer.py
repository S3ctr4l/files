#!/usr/bin/env python3
"""
EC Command Reverse Engineering Tool
Extracts EC commands and sequences from ACPI tables and SPI dumps
"""
import re
import sys
import argparse
from collections import defaultdict, Counter

def parse_acpi_ec_methods(dsl_file):
    """Extract EC commands from ACPI DSL"""
    commands = defaultdict(list)
    
    with open(dsl_file, 'r', errors='ignore') as f:
        content = f.read()
    
    # EC operation patterns in ACPI
    patterns = {
        'write': r'Store\s*\(\s*0x([0-9A-F]+),\s*EC([0-9A-F]+)\)',
        'write_method': r'ECWR\s*\(\s*0x([0-9A-F]+),\s*0x([0-9A-F]+)\)',
        'read': r'ECRD\s*\(\s*0x([0-9A-F]+)\)',
        'query': r'_Q([0-9A-F]{2})\s*\(',  # EC Query events
    }
    
    for cmd_type, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        commands[cmd_type].extend(matches)
    
    return commands

def parse_spi_ec_strings(spi_file):
    """Extract EC-related strings from SPI dump"""
    ec_strings = []
    
    with open(spi_file, 'rb') as f:
        data = f.read()
    
    # Look for EC command signatures
    for i in range(len(data) - 32):
        chunk = data[i:i+32]
        # Try to decode as ASCII
        try:
            text = chunk.decode('ascii', errors='strict')
            if 'EC' in text and any(c in text for c in ['CMD', 'WR', 'RD', 'STA']):
                ec_strings.append(text.strip('\x00'))
        except:
            pass
    
    return list(set(ec_strings))

def generate_ec_header(commands, output_file=None):
    """Generate EC driver header file"""
    output = []
    output.append("/* EC Command Definitions - Auto-generated from reverse engineering */")
    output.append("/* SPDX-License-Identifier: GPL-2.0-only */")
    output.append("")
    output.append("#ifndef EC_HP_IQ526_COMMANDS_H")
    output.append("#define EC_HP_IQ526_COMMANDS_H")
    output.append("")
    output.append("/* EC Command Addresses */")
    
    # Write commands
    if commands.get('write'):
        output.append("\n/* EC Write Commands (extracted from ACPI) */")
        write_addrs = set([addr for addr, _ in commands['write']])
        for addr in sorted(write_addrs, key=lambda x: int(x, 16)):
            output.append(f"#define EC_ADDR_{addr.upper()}  0x{addr}")
    
    # Read commands
    if commands.get('read'):
        output.append("\n/* EC Read Commands */")
        for addr in sorted(set(commands['read']), key=lambda x: int(x, 16)):
            output.append(f"#define EC_READ_{addr.upper()}  0x{addr}")
    
    # Query events
    if commands.get('query'):
        output.append("\n/* EC Query Events (_Qxx methods) */")
        for event in sorted(set(commands['query'])):
            output.append(f"#define EC_EVENT_Q{event.upper()}  0x{event}")
    
    output.append("")
    output.append("#endif /* EC_HP_IQ526_COMMANDS_H */")
    
    result = '\n'.join(output)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(result)
        print(f"Generated: {output_file}")
    else:
        print(result)

def analyze_ec_patterns(commands):
    """Analyze EC command patterns"""
    print("\nEC Command Pattern Analysis")
    print("=" * 60)
    
    if commands.get('write'):
        print(f"\nWrite operations: {len(commands['write'])}")
        # Count most common addresses
        write_addrs = [addr for addr, _ in commands['write']]
        common = Counter(write_addrs).most_common(10)
        print("Most frequently written addresses:")
        for addr, count in common:
            print(f"  0x{addr}: {count} writes")
    
    if commands.get('query'):
        print(f"\nEC Query Events: {len(set(commands['query']))}")
        print(f"Events: {', '.join(sorted(set(commands['query'])))}")

def main():
    parser = argparse.ArgumentParser(description='Reverse engineer EC commands from firmware')
    parser.add_argument('--acpi', help='ACPI DSL file (e.g., DSDT.dsl)')
    parser.add_argument('--spi', help='SPI flash dump')
    parser.add_argument('-o', '--output', help='Output EC header file')
    parser.add_argument('--analyze', action='store_true', help='Show pattern analysis')
    args = parser.parse_args()
    
    if not args.acpi and not args.spi:
        parser.error("At least one of --acpi or --spi required")
    
    commands = defaultdict(list)
    
    if args.acpi:
        print(f"Parsing ACPI: {args.acpi}", file=sys.stderr)
        acpi_cmds = parse_acpi_ec_methods(args.acpi)
        for k, v in acpi_cmds.items():
            commands[k].extend(v)
    
    if args.spi:
        print(f"Parsing SPI dump: {args.spi}", file=sys.stderr)
        ec_strings = parse_spi_ec_strings(args.spi)
        print(f"Found {len(ec_strings)} EC-related strings", file=sys.stderr)
    
    if args.analyze:
        analyze_ec_patterns(commands)
    
    if args.output or not args.analyze:
        generate_ec_header(commands, args.output)

if __name__ == '__main__':
    main()
