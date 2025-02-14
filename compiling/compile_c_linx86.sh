#!/bin/bash

# Check if an argument (C file name without extension) is provided
if [ $# -eq 0 ]; then
    echo "[-] Error: No arguments supplied. Please provide the base name of the C file (without the .c extension)."
    exit 1
fi

# Assign the base name (without extension)
FILENAME="$1"
C_FILE="$FILENAME.c"
OUT_FILE="$FILENAME"
OPTIONS="-fPIC -Os -s"

# Check if the C source file exists
if [ ! -f "$C_FILE" ]; then
    echo "[-] Error: The file '$C_FILE' does not exist."
    exit 1
fi

# Compile the C file with desired options
echo "[+] Compiling '$C_FILE'..."

gcc "$OPTIONS" -o "$OUT_FILE" "$C_FILE"

# Check if the compilation was successful
if [ $? -eq 0 ]; then
    echo "[+] Compilation successful! Executable created: '$OUT_FILE'"
else
    echo "[-] Error: Compilation failed."
    exit 1
fi

