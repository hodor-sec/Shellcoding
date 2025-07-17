#!/bin/bash

# Compiler and options
COMPILER="x86_64-w64-mingw32-gcc-win32"
OPTIONS="-Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections"

# Show help message
show_help() {
    echo "Usage: $0 <source_file.c> [extra_flags...]"
    echo ""
    echo "Build a Windows executable from a C source file using MinGW."
    echo ""
    echo "Arguments:"
    echo "  <source_file.c>   Name of the C source file (must end with .c)"
    echo "  [extra_flags...]  Optional libraries or compiler flags, e.g. -lbcrypt"
    echo ""
    echo "Example:"
    echo "  $0 aes.c -lbcrypt"
}

# No arguments → print help
if [ $# -lt 1 ]; then
    echo "[-] No arguments supplied."
    show_help
    exit 1
fi

# Handle --help or -h
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

# Extract filename and remove from arguments
FILE="$1"
shift

# Check if filename ends with .c
if [[ "$FILE" != *.c ]]; then
    echo "[-] Invalid filename: '$FILE'. You must provide the full .c filename (e.g., aes.c)."
    exit 1
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

# Check if strip is available
if ! command -v x86_64-w64-mingw32-strip &> /dev/null; then
    echo "[-] Stripping tool 'x86_64-w64-mingw32-strip' not found. Please install MinGW binutils."
    exit 1
fi

# Extract base name without .c
BASENAME="${FILE%.c}"

# Show extra libraries/flags if provided
if [ $# -eq 0 ]; then
    echo "[+] No extra libraries or flags provided."
else
    echo "[+] Extra libraries/flags: $@"
fi

# Compile
echo "[+] Compiling '$FILE'..."
$COMPILER "$FILE" $OPTIONS "$@" -o "$BASENAME.exe"

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "[+] Compilation successful! Executable: '$BASENAME.exe'"
else
    echo "[-] Compilation failed."
    exit 1
fi

# Strip symbols
echo "[+] Stripping symbols to reduce size..."
x86_64-w64-mingw32-strip "$BASENAME.exe"

# Show final size
SIZE=$(stat --format="%s" "$BASENAME.exe" 2>/dev/null || wc -c < "$BASENAME.exe")
echo "[+] Final size: $SIZE bytes"

