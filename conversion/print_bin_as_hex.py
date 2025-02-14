#!/usr/bin/env python3

import os
import sys
import binascii

def print_usage():
    """Function to print the usage of the script."""
    print("[#] Usage: " + sys.argv[0] + " <BINFILE>\n")

def read_and_print_hex(filename):
    """Reads a binary file and prints its hex representation in both formats."""
    try:
        with open(filename, 'rb') as f:
            # Read file content and hexlify
            file_content = f.read()
            hex_data = binascii.hexlify(file_content).decode('utf-8')

            # Format the output without \x (just hex digits)
            no_prefix_hex = ''.join(f'{hex_data[i:i+2]}' for i in range(0, len(hex_data), 2))

            # Format the output with \x prefix for each byte
            with_prefix_hex = ''.join(f'\\x{hex_data[i:i+2]}' for i in range(0, len(hex_data), 2))

            # Print both results wrapped in ""
            print("Hex output:")
            print(f'{no_prefix_hex}')
            print("\nHex prefixed with \\x:")
            print(f'"{with_prefix_hex}"\n')

    except FileNotFoundError:
        print(f"[!] Error: File '{filename}' not found.")
        sys.exit(1)
    except IOError as e:
        print(f"[!] IO Error: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(3)

def main():
    # Check if exactly one argument is passed (the BIN file)
    if len(sys.argv) != 2:
        print("[#] Printing hex from BIN file")
        print_usage()
        sys.exit(1)

    # Get filename from command line arguments
    filename = sys.argv[1]

    # Check if the file exists before proceeding
    if not os.path.isfile(filename):
        print(f"[!] Error: '{filename}' is not a valid file.")
        sys.exit(1)

    # Read and print hex content of the file
    read_and_print_hex(filename)

if __name__ == "__main__":
    main()

