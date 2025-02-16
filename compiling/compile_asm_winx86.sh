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
EXE_FILE="$FILENAME.exe"
TEMP_ASM_FILE="$FILENAME.temp.asm"

# Check if the assembly file exists
if [ ! -f "$ASM_FILE" ]; then
    echo "[-] Error: The file '$ASM_FILE' does not exist."
    exit 1
fi

# Process the assembly file: Replace `ptr` with valid NASM syntax
echo "[+] Preprocessing '$ASM_FILE' to remove 'ptr'..."
sed 's/\bptr\b//g' "$ASM_FILE" > "$TEMP_ASM_FILE"

# Assemble the .asm file
echo "[+] Assembling '$TEMP_ASM_FILE' with Nasm..."
nasm -f $OSARCH -o $OBJ_FILE "$TEMP_ASM_FILE"
if [ $? -ne 0 ]; then
    echo "[-] Error: Assembly failed."
    exit 1
fi

# Link the object file into a binary
echo "[+] Linking '$OBJ_FILE' to create '$EXE_FILE'..."
ld -m $BINARCH -o $EXE_FILE $OBJ_FILE
if [ $? -ne 0 ]; then
    echo "[-] Error: Linking failed."
    exit 1
fi

# Clean up temporary file
rm "$TEMP_ASM_FILE"

# Success message
echo "[+] Done! Binary '$EXE_FILE' created successfully."

