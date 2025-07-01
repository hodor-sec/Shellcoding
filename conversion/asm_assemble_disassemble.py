# Example:
#
# $ python3 asm_assemble_disassemble.py -l py -f test.asm
# [+] ASM converted to HEX escaped:
#     \xcd\x03\x31\xc0
#
# [+] ASM converted to HEX:
#     cd0331c0
#
# [+] HEX disassembled instructions for py:
#     shellcode = {
#                 b"\xcd\x03"              # 0x0         int  3
#                 b"\x31\xc0"              # 0x2         xor  eax, eax
#     }

import traceback
import argparse
import binascii
from os.path import exists
from keystone import *
from capstone import *

# Define a list of known issues
known_issues = """
Known Issues:
- Issue 1: Keystone (and thus Python) might hang reading too complex ASM files
- Issue 2: Keystone WILL hang on non-predefined labels and jumping to said labels
- Issue 3: Keystone has issues with some NASM accepted syntax, specifically pointers, e.g. "call dword [eax]", instead of "call dword ptr [eax]"
"""

# Badchars
badchars = []

# Fancy colors
class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"
    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    else:
        # set Windows console in VT mode
        if __import__("platform").system() == "Windows":
            kernel32 = __import__("ctypes").windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32

# Example partial ASM code
sample_asm_x86 = (
        " start:                                ;"  #
        "    int3                               ;"  # REMOVE WHEN NOT DEBUGGING
        "    mov ebp, esp                       ;"  #
        "    sub esp, 60h                       ;"  #
        "    push 0x00000000                    ;"
        "    push 0x00112200;"
        "   ;                       "
        " find_kernel32:                        ;"  #
        "    xor ecx,ecx                        ;"  # ECX = 0
        "    mov esi,fs:[ecx+30h]               ;"  # ESI = &(PEB) ([FS:0x30])
        "    mov esi,[esi+0Ch]                  ;"  # ESI = PEB->Ldr
        "    mov esi,[esi+1Ch]                  ;"  # ESI = PEB->Ldr.InitOrder

        " next_module:                          ;"  #
        "    mov ebx,[esi+8h]                   ;"  # EBX = InInitOrder[X].base_address
        "    mov edi,[esi+20h]                  ;"  # EDI = InInitOrder[X].module_name
        "    mov esi,[esi]                      ;"  # ESI = InInitOrder[X].flink
        "    cmp [edi+12*2], cx                 ;"  # (unicode) modulename[12] == 0x00?
        "    jne next_module                    ;"  # No; try next module
        "    ret                                ;"  # RET
)
sample_asm_x64 = (
    " start:                                    ;"  #
    "   int3                                    ;"  #
    "   add rsp, 0xfffffffffffffdf8             ;"  # Avoid Null Byte
    " locate_kernel32:                          ;"
    "   xor rcx, rcx                            ;"  # Zero RCX contents
    "   mov rax, gs:[rcx + 0x60]                ;"  # 0x060 ProcessEnvironmentBlock to RAX.
    "   mov rax, [rax + 0x18]                   ;"  # 0x18  ProcessEnvironmentBlock.Ldr Offset
    "   mov rsi, [rax + 0x20]                   ;"  # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
    "   lodsq                                   ;"  # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
    "   xchg rax, rsi                           ;"  # Swap RAX,RSI
    "   lodsq                                   ;"  # Load qword at address (R)SI into RAX
    "   mov rbx, [rax + 0x20]                   ;"  # RBX = Kernel32 base address
    "   mov r8, rbx                             ;"  # Copy Kernel32 base address to R8 register
    #" ; Code for parsing Export Address Table   ;"
    "   mov ebx, [rbx+0x3C]                     ;"  # Get Kernel32 PE Signature (offset 0x3C) into EBX
    "   add rbx, r8                             ;"  # Add defrerenced signature offset to kernel32 base. Store in RBX.
    "   mov edx, [rbx+0x88]                     ;"  # Offset from PE32 Signature to Export Address Table (NULL BYTE)
    "   xor r12,r12                             ;"
    "   add r12, 0x88FFFFF                      ;"
    "   shr r12, 0x14                           ;"
    "   mov edx, [rbx+r12]                      ;"  # Offset from PE32 Signature to Export Address Table
    "   add rdx, r8                             ;"  # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
    "   mov r10d, [rdx+0x14]                    ;"  # Number of functions
    "   xor r11, r11                            ;"  # Zero R11 before use
    "   mov r11d, [rdx+0x20]                    ;"  # AddressOfNames RVA
    "   add r11, r8                             ;"  # AddressOfNames VMA
)

# Handle CTRL-C
def keyboard_interrupt():
    """Handles keyboardinterrupt exceptions"""""
    print("\n\n[*] User requested an interrupt, exiting...")
    exit(1)

# Assemble binary instructions to ASM code
def assemble(code, ks_arch,ks_mode, addr=0, debug=False):
    try:
        bincode = ""
        eng = Ks(ks_arch, ks_mode)
        asmbuf, count = eng.asm(code)
        if debug:
            print("%s = %s" %(code, asmbuf))
        for enc in asmbuf:
            bincode += "\\x{0:02x}".format(enc)
        return asmbuf, bincode
    except KsError as e:
        print("[!] Assembling error: %s" %e)
        # get count via e.get_asm_count()
        count = e.get_asm_count()
        if count is not None:
            # print out the number of instructions succesfully compiled
            print("ASM instruction compiled: %u" %e.get_asm_count())
        # Get the instruction that caused the error (based on count)
        if count is not None and count < len(code.splitlines()):
            error_line = code.splitlines()[count]
            print(f"[!] Error occurred on line {count + 1}: {error_line.strip()}")
        exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        traceback.print_exc()
        exit(1)

# Helper function to calculate the visible length of a string with colors
def get_visible_length(byte_str):
    # Count the length of the byte string, excluding color codes
    # Color codes are between Colors.RED and Colors.END
    return len(byte_str.replace(Colors.RED, "").replace(Colors.END, ""))

# Check assembly instructions, line by line
def check_asm(buffer, ks_arch, ks_mode):
    res = []
    try:
        # Initialize the Keystone assembler
        ks = Ks(ks_arch, ks_mode)

        # Try to assemble each line individually
        for line_num, line in enumerate(buffer, 1):
            try:
                ks.asm(line)  # Try to assemble each line
            except KsError as e:
                res.append((line_num, line, str(e)))

    except KsError as e:
        # Catch any general errors from keystone and return failure
        res.append("Error", "Keystone initialization error", str(e))
    return res

# Disassemble instructions
def disassemble(lang,var,asmbuf,cs_arch,cs_mode):
    if not asmbuf:
        raise ValueError("[!] Assembled buffer is empty!")
    md = Cs(cs_arch,cs_mode)
    # Customize the mnemonic of "data" instruction
    md.skipdata_setup = ("db", None, None)
    # Turn on SKIPDATA mode
    md.skipdata = True
    # Initialize buffer
    disasmbuf = ""

    # Check which language
    if lang == "py":
        prefix = var + " = (\n"
        comment = "#"
        firstchar = "b"
        suffix = ")\n"
    elif lang == "c":
        prefix = "unsigned char " + var + "[] = \\\n"
        comment = "//"
        firstchar = ""
        suffix = ";\n"

    # Loop ASM buffer
    for i in md.disasm(asmbuf, 0x00):
        bytes_str = []
        # Check and color bad chars
        lenbc = 0
        opcodewidth = 50
        for c in i.bytes:
            fmtbyte = "{:02x}".format(c)
            if c in badchars:
                fmtbyte = Colors.RED + fmtbyte + Colors.END
                lenbc += get_visible_length(fmtbyte) // 2
            bytes_str.append(fmtbyte)

        while lenbc != 0:
            opcodewidth += 11
            lenbc -= 1

        # Create buf
        opcode = firstchar
        opcode += "\"\\x"
        opcode += "\\x".join(bytes_str)
        opcode += "\""
        disasmbuf += '\t{0:<{width}}\t{1:1} {2:<3} / {3:<3} \t\t {4:0} {5:0}\n'.format(opcode,comment,i.address,hex(i.address),i.mnemonic,i.op_str,width=opcodewidth)

    return prefix + disasmbuf + suffix

# Convert to ASM, binary, hex
def convert_asm(buffer,ks_arch,ks_mode):
    try:
        # Assemble
        asmcode,bincode = assemble(buffer,ks_arch,ks_mode)
        # Convert assembled buffer to hex string
        hexbuf = "".join(f"{byte:02x}" for byte in asmcode)
        # Calculate the number of hex characters
        hexcount = len(hexbuf) // 2
        return bincode, hexbuf, hexcount
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        exit(1)

# Replace comments with escaping characters
# Still buggy
def replaceComment(fileBuffer):
    output = []
    asmcommentchar = ";"
    pycommentchar = "#"
    for line in fileBuffer:
        # Check if the line contains an ASM comment
        if asmcommentchar in line:
            # Replace the first occurrence of ';' with '#'
            line = line.split(asmcommentchar, 1)[0] + asmcommentchar + pycommentchar + line.split(asmcommentchar, 1)[1]
        # Append the line (modified or not) to the output list
        output.append(line)
    # Join the list into a single string with newlines between lines
    return output

# Remove comments in buffer; both start with comments and inline
def removeComments(fileBuffer):
    output = []
    commentchars = [";","#"]

    for line in fileBuffer:
        for commentchar in commentchars:
            if commentchar in line:
                line = line.split(commentchar, 1)[0].rstrip()
                break
        if not line.isspace():
            if line:
                line.strip()
                output.append(line)
    return output

# Remove potential headers from ASM files
# Keysone doesn't always like all headers and still might error, even after removal
def skipHeader(fileBuffer):
    header_markers = ["_start:", "BITS 32","bits 32", "bits 64", "[global]", ";", "section", "extern"]
    skip = True
    newLines = []

    for line in fileBuffer:
        if skip:
            if any(line.strip().startswith(marker) for marker in header_markers):
                print(f"Skipping header: {line.strip()}")
                continue
            else:
                skip = False
        if not line.isspace():
            if line:
                newLines.append(line)
    return newLines

# Attempt to read ASM file
def read_asmfile(filename):
    try:
        with open(filename) as fn:
            lines = fn.readlines()
            lines = skipHeader(lines)
            lines = removeComments(lines)
            #errlines = check_asm(lines)
            """
            if errlines:
                print("[!] Keystone failed on following instructions:\n")
                for line in errlines:
                    print("ASM line " + str(line[0]) + "; instruction: " + line[1] + "\n\terror: " + line[2])
                print("\n[!] Fix these lines before trying again, exiting...\n")
                exit(1)
            """
            # lines = replaceComment(lines)
            return '\n'.join(lines)
    except (FileNotFoundError, IOError) as ex:
        print("[!] File not found: " + str(ex) + ".\n")
        exit(1)
    except Exception:
        traceback.print_exc()
        exit(1)

# Attempt to read BIN file
def read_binfile(filename):
    try:
        with open(filename,'rb') as fn:
            fcontent = fn.read()
            hex_data = binascii.hexlify(fcontent).decode('utf-8')
            return hex_data
    except (FileNotFoundError, IOError) as ex:
        print("[!] File not found: " + str(ex) + ".\n")
        exit(1)
    except Exception:
        traceback.print_exc()
        exit(1)

# Parse the badhcars given as argument
def parse_badchars(badchars_str):
    if badchars_str:
        # Remove any leading backslashes or 'x' and split by '\\x' to get individual hex byte pairs
        badchars.extend(int(c, 16) for c in badchars_str.split('\\x') if c)
    else:
        return False

# Main
def main(args):
    # Do stuff
    try:
        cs_arch = CS_ARCH_X86
        ks_arch = KS_ARCH_X86
        # Process mode
        if args.mode == "64":
            cs_mode = CS_MODE_64
            ks_mode = KS_MODE_64
            sample_asm = sample_asm_x64
        else:
            cs_mode = CS_MODE_32
            ks_mode = KS_MODE_32
            sample_asm = sample_asm_x86
        # Parse badchars
        if args.badchars:
            parse_badchars(args.badchars)
        # Process hexstring
        if args.hexstring:
            # Process and disassemble hexstring
            size = len(args.hexstring) // 2
            disassembled = disassemble(args.lang, args.var, bytes.fromhex(args.hexstring),cs_arch,cs_mode)
            print(f"[+] HEX disassembled string for {args.lang}:\n{disassembled}")
            print(f"[+] Size: {size}\n")
        elif args.binfile:
            # Read from file
            buffer = read_binfile(args.binfile)
            # Process and disassemble hexstring
            size = len(buffer) // 2
            disassembled = disassemble(args.lang, args.var, bytes.fromhex(buffer),cs_arch,cs_mode)
            print(f"[+] HEX disassembled string for {args.lang}:\n{disassembled}")
            print(f"[+] Size: {size}\n")
        elif args.asmfile:
            # Read from file
            buffer = read_asmfile(args.asmfile)
            binbuf, hexbuf, hexcount = convert_asm(buffer,ks_arch,ks_mode)
            disassembled = disassemble(args.lang, args.var, bytes.fromhex(hexbuf),cs_arch,cs_mode)
            # Nicely print output
            print(f"[+] ASM converted to HEX escaped:\n{binbuf}\n")
            print(f"[+] ASM converted to HEX:\n{hexbuf}\n")
            print(f"[+] HEX disassembled string for {args.lang}:\n{disassembled}")
            print(f"[+] Size: {hexcount}\n")
        else:
            # If no hexstring, use hardcoded asm
            binbuf, hexbuf, hexcount = convert_asm(sample_asm,ks_arch,ks_mode)
            disassembled = disassemble(args.lang, args.var, bytes.fromhex(hexbuf),cs_arch,cs_mode)
            # Nicely print output
            print(f"[+] ASM converted to HEX escaped:\n{binbuf}\n")
            print(f"[+] ASM converted to HEX:\n{hexbuf}\n")
            print(f"[+] HEX disassembled string for {args.lang}:\n{disassembled}")
            print(f"[+] Size: {hexcount}\n")
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        traceback.print_exc()
        exit(1)
    except KeyboardInterrupt:
        keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    """Parse and return the command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Custom Python ASM assembler and disassembler using keystone and capstone. ',
        epilog=known_issues,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--lang", "-l", required=True, choices=["py", "c"], help="Output language style: 'py' for Python or 'c' for C. Required")
    parser.add_argument("--mode", "-m", required=True, choices=["32", "64"], help="32 or 64 bits mode. Required")
    parser.add_argument("--asmfile", required=False, help="ASM file containing instructions (no comments/headers). Optional")
    parser.add_argument("--binfile", required=False, help="BIN file containing binary payload. Optional")
    parser.add_argument("--hexstring", "-hs", required=False, help="Hex-encoded string to disassemble. Optional")
    parser.add_argument("--badchars", "-b", required=False, help="Bad characters to avoid in shellcode (hex-encoded, e.g. '\\x0a\\x0d\\x00'). Coloured output. Optional")
    parser.add_argument("--var", "-v", required=False, default="shellcode", help="The name of the Python variable for storing shellcode. Optional")

    args = parser.parse_args()

    main(args)

