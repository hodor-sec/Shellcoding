#!/usr/bin/env python

import os
import sys
import binascii

# Check arguments
if (len(sys.argv) != 2):
    print("[#] Printing hex from BIN file")
    print("[#] Usage: " + sys.argv[0] + " <BINFILE>\n")
    exit(-1)

# Filename as binary argument
filename = sys.argv[1]

# Attempt to read file
try:
    with open(filename, 'rb') as f:
        res = binascii.hexlify(f.read())
        print(res.decode('utf-8'))
except (FileNotFoundError, IOError) as ex:
    print("[!] File not found: " + str(ex) + ".\n")
    exit(-1)
except Exception as ex:
    print("[!] Error: " + str(ex) + ".\n")
    exit(-1)

