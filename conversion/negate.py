import sys
import re

def is_valid_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))

def negate_twos_complement(input_hex: str, bit_width: int) -> str:
    # Convert input to integer and mask it to bit width
    value = int(input_hex, 16) & ((1 << bit_width) - 1)
    mask = (1 << bit_width) - 1

    # XOR with mask (bitwise NOT), then add 1
    negated = (value ^ mask) + 1
    negated &= mask  # Ensure result fits within bit width

    return f"0x{negated:0{bit_width // 4}x}"

def main():
    if len(sys.argv) < 3:
        print("Usage: python hexxor.py <hex_value> <--x86|--x64>")
        sys.exit(1)

    input_hex = sys.argv[1].lower().replace("0x", "")
    mode = sys.argv[2]

    if not is_valid_hex(input_hex):
        print("Error: Input must be a valid hexadecimal string.")
        sys.exit(1)

    if mode == "--x86":
        bit_width = 32
    elif mode == "--x64":
        bit_width = 64
    else:
        print("Error: Mode must be --x86 or --x64")
        sys.exit(1)

    result = negate_twos_complement(input_hex, bit_width)
    print(result)

if __name__ == "__main__":
    main()

