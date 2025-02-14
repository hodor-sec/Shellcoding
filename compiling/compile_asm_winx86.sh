#!/bin/bash

# Configuration: target architecture and binary format
OSARCH="win32"
BINARCH="i386pe"

# Check if a filename argument is provided
if [ $# -eq 0 ]; then
    echo "[-] Error: No arguments supplied. Please provide the base name of the assembly file (without the .asm extension)."
    exit 1
fi

# Assign the base name (without extension)
FILENAME="$1"
ASM_FILE="$FILENAME.asm"
OBJ_FILE="$FILENAME.o"
BIN_FILE="$FILENAME.bin"

# Check if the assembly file exists
if [ ! -f "$ASM_FILE" ]; then
    echo "[-] Error: The file '$ASM_FILE' does not exist."
    exit 1
fi

# Assemble the .asm file
echo "[+] Assembling '$ASM_FILE' with Nasm..."
nasm -f $OSARCH -o $OBJ_FILE $ASM_FILE
if [ $? -ne 0 ]; then
    echo "[-] Error: Assembly failed."
    exit 1
fi

# Link the object file into a binary
echo "[+] Linking '$OBJ_FILE' to create '$BIN_FILE'..."
ld -m $BINARCH -o $BIN_FILE $OBJ_FILE
if [ $? -ne 0 ]; then
    echo "[-] Error: Linking failed."
    exit 1
fi

# Success message
echo "[+] Done! Binary '$BIN_FILE' created successfully."

