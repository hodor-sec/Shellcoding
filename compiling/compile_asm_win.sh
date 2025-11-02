#!/usr/bin/env bash
# Build a Windows PE executable or DLL from NASM source using ld directly.
# Supports both x86 (win32) and x64 (win64).
#
# Usage:
#   ./build.sh [-a ARCH] [-e ENTRY] [-t TYPE] [-d] <asm-file.asm> [extra libs...]
#
# Example:
#   ./build.sh -a x64 factorial.asm -lkernel32 -lmsvcrt
#   ./build.sh -a x86 hello.asm -t dll
#   ./build.sh -e _start -a x86 myprog.asm
#
# Requirements: nasm, MinGW-w64 toolchain (x86_64 or i686), optional strip

set -euo pipefail

# --- Default settings ---
ARCH="x64"
OSARCH="win64"
BINARCH="i386pep"
OUTPUT_TYPE="exe"
ENTRY_POINT=""
DEBUG=false

cleanup() {
    [[ -f "${TEMP_ASM_FILE:-}" ]] && rm -f "$TEMP_ASM_FILE"
}
trap cleanup EXIT INT TERM

show_help() {
    cat <<EOF
Usage: $0 [-a ARCH] [-e ENTRY] [-t TYPE] [-d] <asm-file.asm> [extra libs...]

Build a Windows PE executable or DLL from NASM source using ld directly.

Options:
  -a ARCH      Target architecture: x64 | x86   (default: x64)
  -e ENTRY     Specify custom entry point (e.g., _start)
  -t TYPE      Output type: exe | dll           (default: exe)
  -d           Enable debug output
  -h           Show this help and exit

Examples:
  $0 -a x64 hello.asm -lmsvcrt -lkernel32
  $0 -a x86 -t dll hello.asm -lkernel32
  $0 -e _start -a x86 mylib.asm
EOF
}

# --- Parse arguments ---
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a)
            ARCH="$2"
            shift 2
            ;;
        --arch=*)
            ARCH="${1#--arch=}"
            shift
            ;;
        -e)
            ENTRY_POINT="$2"
            shift 2
            ;;
        --entry=*)
            ENTRY_POINT="${1#--entry=}"
            shift
            ;;
        -t)
            OUTPUT_TYPE="$2"
            shift 2
            ;;
        --type=*)
            OUTPUT_TYPE="${1#--type=}"
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            ARGS+=("$1")
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# --- Architecture selection ---
case "$ARCH" in
    x64|amd64)
        OSARCH="win64"
        BINARCH="i386pep"
        MINGW_PREFIX="x86_64-w64-mingw32"
        ;;
    x86|i386)
        OSARCH="win32"
        BINARCH="i386pe"
        MINGW_PREFIX="i686-w64-mingw32"
        ;;
    *)
        echo "Error: invalid architecture '$ARCH' (must be x86 or x64)."
        exit 1
        ;;
esac

echo "[+] Target architecture: $ARCH ($OSARCH / $BINARCH)"

# --- Find appropriate toolchain executables ---
find_tool() {
    local tool="$1"
    if command -v "${MINGW_PREFIX}-${tool}" >/dev/null 2>&1; then
        echo "${MINGW_PREFIX}-${tool}"
    elif command -v "$tool" >/dev/null 2>&1; then
        echo "$tool"
    else
        echo ""
    fi
}

NASM_BIN="$(find_tool nasm)"
LD_BIN="$(find_tool ld)"
STRIP_BIN="$(find_tool strip)"

if [ -z "$NASM_BIN" ] || [ -z "$LD_BIN" ]; then
    echo "Error: could not find suitable nasm/ld for architecture '$ARCH'."
    echo "Please ensure MinGW-w64 toolchain is installed (e.g. ${MINGW_PREFIX}-ld)."
    exit 1
fi

# --- Validate input ---
ASM_FILE=""
EXTRA_LIBS=()

for arg in "${ARGS[@]}"; do
    if [[ "$arg" == *.asm ]]; then
        ASM_FILE="$arg"
    else
        EXTRA_LIBS+=("$arg")
    fi
done

if [ -z "$ASM_FILE" ]; then
    echo "Error: no ASM file specified."
    show_help
    exit 1
fi

if [[ "$OUTPUT_TYPE" != "exe" && "$OUTPUT_TYPE" != "dll" ]]; then
    echo "Error: invalid output type '$OUTPUT_TYPE' (must be exe or dll)."
    exit 1
fi

if [ ! -f "$ASM_FILE" ]; then
    echo "Error: file '$ASM_FILE' not found."
    exit 1
fi

BASE_NAME="$(basename "$ASM_FILE" .asm)"
OBJ_FILE="$BASE_NAME.o"
OUTPUT_FILE="$BASE_NAME.$OUTPUT_TYPE"
TEMP_ASM_FILE="$(mktemp "${BASE_NAME}_XXXX.asm")"

echo "[+] Preprocessing '$ASM_FILE'..."
sed 's/\bptr\b//g' "$ASM_FILE" > "$TEMP_ASM_FILE"

echo "[+] Assembling with NASM ($OSARCH)..."
"$NASM_BIN" -f "$OSARCH" -o "$OBJ_FILE" "$TEMP_ASM_FILE"

# --- Detect MinGW library path ---
MINGW_LIB_PATHS=(
    "/usr/$MINGW_PREFIX/lib"
    "/usr/lib/$MINGW_PREFIX"
    "/usr/lib/gcc/$MINGW_PREFIX/$(gcc -dumpversion 2>/dev/null || true)"
)

LIB_PATH=""
for path in "${MINGW_LIB_PATHS[@]}"; do
    if [ -d "$path" ]; then
        LIB_PATH="$path"
        break
    fi
done

if [ -z "$LIB_PATH" ]; then
    echo "[!] Warning: could not find MinGW library path."
else
    echo "[+] Using library path: $LIB_PATH"
fi

# --- Entry point info ---
if [ -n "$ENTRY_POINT" ]; then
    echo "[+] Using entry point: $ENTRY_POINT"
else
    echo "[+] Using default system entry point"
fi

# --- Build linker command ---
LD_CMD=("$LD_BIN" "-m" "$BINARCH" "-o" "$OUTPUT_FILE" "$OBJ_FILE")
[ -n "$LIB_PATH" ] && LD_CMD+=("-L$LIB_PATH")

if [ "$OUTPUT_TYPE" == "dll" ]; then
    echo "[+] Linking as DLL..."
    LD_CMD+=("-shared")
else
    echo "[+] Linking as EXE..."
fi

[ -n "$ENTRY_POINT" ] && LD_CMD+=("-e" "$ENTRY_POINT")

LD_CMD+=("-lkernel32" "-lmsvcrt")
LD_CMD+=("${EXTRA_LIBS[@]}")

$DEBUG && echo "[DEBUG] ${LD_CMD[*]}"
"${LD_CMD[@]}"

if [ -n "$STRIP_BIN" ]; then
    echo "[+] Stripping '$OUTPUT_FILE'..."
    "$STRIP_BIN" "$OUTPUT_FILE" || echo "[!] Strip failed (non-fatal)."
else
    echo "[!] 'strip' not found; skipping."
fi

echo "[+] Done: created '$OUTPUT_FILE'"

