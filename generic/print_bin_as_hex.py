#!/usr/bin/env python

import os
import sys
import binascii

# Check arguments
if (len(sys.argv) != 2):
    print "[#] Printing hex from BIN file"
    print "[#] Usage: " + sys.argv[0] + " <BINFILE>\n"
    exit(-1)

# Filename as binary argument
filename = sys.argv[1]

# Attempt to read file
try:
    with open(filename, 'rb') as f:
        print binascii.hexlify(f.read())
except:
    print "[!] File not found.\n"
    exit(-1)

