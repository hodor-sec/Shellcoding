#!/bin/bash

# Compiler and options
COMPILER="x86_64-w64-mingw32-gcc-win32"
OPTIONS="-Os -s -fPIC"

# Check if a C file name is provided as argument
if [ $# -eq 0 ]; then
    echo "[-] No arguments supplied. Please provide the name of the C file (without the .c extension)."
    exit 1
fi

# Extract the file name and add ".c" extension if missing
FILE="$1"
if [[ ! "$FILE" =~ \.c$ ]]; then
    FILE="$FILE.c"
fi

# Ensure the file exists
if [ ! -f "$FILE" ]; then
    echo "[-] The file '$FILE' does not exist."
    exit 1
fi

# Check if the compiler is available
if ! command -v "$COMPILER" &> /dev/null; then
    echo "[-] Compiler '$COMPILER' not found. Please ensure it's installed and in your PATH."
    exit 1
fi

# Extract the base name (without extension) for the output
BASENAME="${FILE%.c}"

# Compile the C file
echo "[+] Compiling '$FILE' with $COMPILER..."
$COMPILER "$FILE" $OPTIONS -o "$BASENAME.exe"

# Check if the compilation was successful
if [ $? -eq 0 ]; then
    echo "[+] Compilation successful! Executable: '$BASENAME.exe'"
else
    echo "[-] Compilation failed."
    exit 1
fi

