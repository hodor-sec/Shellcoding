import sys

def is_valid_hex(s):
    """Check if the string s is a valid hex number."""
    try:
        # Remove the '0x' prefix if present, then check if it's a valid hex number
        int(s, 16)
        return True
    except ValueError:
        return False

def hexxor(a, b):
    """XOR two hex strings of the same length, padding shorter ones with leading zeros if necessary."""
    # Pad the shorter hex string with leading zeros to match the length of the longer one
    max_length = max(len(a), len(b))
    a = a.zfill(max_length)
    b = b.zfill(max_length)

    return "".join(format(int(x, 16) ^ int(y, 16), 'x') for x, y in zip(a, b))

def main():
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python3 hexxor.py <hex_string>")
        sys.exit(1)

    # Get the second hex string from command line argument
    b = sys.argv[1]
    a = 'fffffffe'  # Fixed hex string for a (can be changed if needed)

    # Strip the '0x' prefix if present
    if b.startswith('0x'):
        b = b[2:]

    # Validate both hex strings
    if not is_valid_hex(a):
        print(f"Error: '{a}' is not a valid hex string.")
        sys.exit(1)

    if not is_valid_hex(b):
        print(f"Error: '{b}' is not a valid hex string.")
        sys.exit(1)

    # XOR the hex strings and print the result with '0x' prefix
    try:
        result = hexxor(a, b)
        print(f"Result of XOR: 0x{result}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

