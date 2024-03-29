#!/usr/bin/python
# Author: hodorsec
# Filename: rolling-xor-encoder-random.py
# Python Rolling XOR Encoder random byte as first byte
# Checks on bad characters as well
#
# Version 0.7
# - Fixed odd size error using binascii
# Version 0.6
# - Moved to Python3; removed ord() calls as it's redundant for Py3
# Version 0.5:
# - Fixed bad character checking
# - Added binary file reading as argument

import os
import sys
import random
import binascii
import traceback

# Check arguments
if (len(sys.argv) != 2):
    print("[#] Rolling XOR encoder script")
    print("[#] Generates a XOR'ed string as HEX and DB ASM output, XOR'ed by a initial random number. Checks for bad characters in output.\n")
    print("[#] Usage: " + sys.argv[0] + " <BINFILE>\n")
    exit(-1)

# Filename as binary argument
filename = sys.argv[1]

# Set empty variable
shellcode = []

# Attempt to read file
try:
    with open(filename, 'rb') as f:
        temp = binascii.hexlify(f.read()).decode()
        # temp2 = binascii.a2b_hex(f.read().strip())
        # print(temp2)
        shellcode = binascii.unhexlify(''.join(str(v) for v in temp))
        # shellcode = temp
except (FileNotFoundError, IOError) as ex:
    print("[!] File not found: " + str(ex) + ".\n")
    exit(-1)
except Exception as ex:
    print("[!] Error: " + str(ex) + ".\n")
    exit(-1)

# Possible badbytes
badbytes = (b"\x0a\x0b\x0d\x00\x0c\x20\x09")

# Initialize PRNG
def initRandom():
    return random.randint(1,255)

# Do a for loop, iterating over the bytearray for each byte in shellcode
# Check on bad bytes by XOR'ing a character by the initial random number and breaking up if result is a badchar
def encode():
    encoded_result = []
    randomint = initRandom()
    encoded_result.append(randomint)
    for x in range(0, len(shellcode)):
        xorred_byte = (shellcode[x] ^ encoded_result[x])
        for y in range(0, len(badbytes)):
            if (xorred_byte == badbytes[y]):
                print("Bad random number: " + str(randomint) + " \"\\x%02x\" on shellcode character \"\\x%02x\" for bad character \\x%02x: XORRED result is \\x%02d" % (randomint, shellcode[x], badbytes[y], xorred_byte))
                return None
        encoded_result.append(xorred_byte)
    print("\nGood random number: " + str(randomint))
    return encoded_result

print('[*] Encoding shellcode ...')
encoded = []
while not encoded:
    encoded = encode()

if encoded:
    # HEX variant
    hex_coded = "\"" + ("".join("\\x%02x" %c for c in encoded)) + "\""
    # ASM variant
    asm_coded = "EncodedShellcode: db " + (",".join("0x%02x" %c for c in encoded))

    # Print format for hex shellcode, e.g. \xaa\xbb\xcc, etc
    print("\n[*] Hex shellcode")
    print(hex_coded)

    # Print format for ASM shellcode, e.g. 0xAA, 0xBB, etc
    print("\n[*] ASM shellcode")
    print(asm_coded)

    # Print the length of the shellcode
    print('\n[*] Length: %d' % (len(encoded)-1))
