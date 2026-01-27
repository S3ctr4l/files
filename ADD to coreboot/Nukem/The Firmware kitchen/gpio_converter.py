#!/usr/bin/env python3
"""
GPIO Configuration Converter
Converts inteltool GPIO dumps to coreboot pad configuration format
"""
import re
import sys
import argparse

# GPIO pad configuration mappings
PAD_MODES = {
    0x44000400: "GPO",  # GPIO Output
    0x44000600: "GPI",  # GPIO Input
    0x44000200: "NF",   # Native Function
}

def parse_inteltool_gpio(filepath):
    """Parse inteltool GPIO dump"""
    gpios = []
    
    with open(filepath, 'r') as f:
        for line in f:
            # Match lines like: GPIO_42: 0x44000400
            match = re.search(r'GPP?_?([A-Z]?\d+):\s*0x([0-9A-F]{8})', line, re.I)
            if match:
                gpio_name, value_hex = match.groups()
                value = int(value_hex, 16)
                gpios.append((gpio_name, value))
    
    return gpios

def value_to_pad_config(gpio_name, value):
    """Convert register value to coreboot macro"""
    
    # Determine mode from register bits
    if value & 0x00000800:  # Bit 11 = input
        return f"PAD_CFG_GPI(GPP_{gpio_name}, NONE, DEEP)"
    elif value & 0x00002000:  # Bit 13 = GPIO mode
        if value & 0x00000001:  # Bit 0 = output value
            return f"PAD_CFG_GPO(GPP_{gpio_name}, 1, DEEP)"
        else:
            return f"PAD_CFG_GPO(GPP_{gpio_name}, 0, DEEP)"
    else:  # Native function
        func_num = (value >> 10) & 0x0F
        return f"PAD_CFG_NF(GPP_{gpio_name}, NONE, DEEP, NF{func_num})"

def generate_gpio_c(gpios, output_file=None):
    """Generate complete gpio.c file"""
    output = []
    output.append("/* GPIO Configuration - Auto-generated from inteltool */")
    output.append("/* SPDX-License-Identifier: GPL-2.0-only */")
    output.append("")
    output.append("#include <soc/gpio.h>")
    output.append("")
    output.append("static const struct pad_config gpio_table[] = {")
    
    for gpio_name, value in gpios:
        pad_config = value_to_pad_config(gpio_name, value)
        output.append(f"    {pad_config},  /* 0x{value:08X} */")
    
    output.append("};")
    output.append("")
    output.append("const struct pad_config *variant_gpio_table(size_t *num)")
    output.append("{")
    output.append("    *num = ARRAY_SIZE(gpio_table);")
    output.append("    return gpio_table;")
    output.append("}")
    
    result = '\n'.join(output)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(result)
        print(f"Generated: {output_file}")
    else:
        print(result)

def main():
    parser = argparse.ArgumentParser(description='Convert inteltool GPIO dump to coreboot format')
    parser.add_argument('input', help='inteltool GPIO output file')
    parser.add_argument('-o', '--output', help='Output gpio.c file')
    args = parser.parse_args()
    
    gpios = parse_inteltool_gpio(args.input)
    print(f"Parsed {len(gpios)} GPIO configurations", file=sys.stderr)
    
    generate_gpio_c(gpios, args.output)

if __name__ == '__main__':
    main()
