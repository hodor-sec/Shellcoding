# Example:
#
# $ python3 asm_assemble_disassemble.py -l py -f test.asm
# [+] Orginal code:
#     int 3
#     xor eax,eax
#
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

import binascii
import traceback
import argparse
import sys
from os.path import exists
from keystone import *
from capstone import *

CODE = (
        " start:                                ;"  #
        "    int3                               ;"  # REMOVE WHEN NOT DEBUGGING
        "    mov ebp, esp                       ;"  #
        "    sub esp, 60h                       ;"  #

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

# Handle CTRL-C
def keyboard_interrupt():
    """Handles keyboardinterrupt exceptions"""""
    print("\n\n[*] User requested an interrupt, exiting...")
    exit(1)

# Assemble instructions for binary
def assembleasm(code, addr = 0, mode = keystone.KS_MODE_32):
    ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
    encoding, count = ks.asm(code, addr)
    binbuf = bytearray(b"")
    for c in encoding:
        binbuf.append(c)
    return binbuf, count

# Assemble instructions for hex strings
def assemblebin(code, addr = 0, mode = keystone.KS_MODE_32):
    ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
    encoding, count = ks.asm(code, addr)
    binbuf = "".join(chr(c) for c in encoding)
    return binbuf, count

# Disassemble instructions
def disassemble(lang,var,asmbuf):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    # Customize the mnemonic of "data" instruction
    md.skipdata_setup = ("db", None, None)
    # Turn on SKIPDATA mode
    md.skipdata = True

    disasmbuf = ""

    # Check which language
    if lang == "py":
        prefix = var + " = {\n"
        comment = "#"
        firstchar = "b"
        suffix = "}\n"
    elif lang == "c":
        prefix = "unsigned char " + var + "[] = \\\n"
        comment = "//"
        firstchar = ""
        suffix = ";\n"

    # Loop ASM buffer
    for i in md.disasm(asmbuf, 0x00):
        opcode = firstchar + "\"\\x" + "\\x".join("{:02x}".format(c) for c in i.bytes) + "\""
        disasmbuf += f"\t{opcode:<35}" + comment + " "
        disasmbuf += f"0x{i.address:<10}"
        disasmbuf += f"{i.mnemonic:<5}"
        disasmbuf += f"{i.op_str:<10}\n"

    return prefix + disasmbuf + suffix

def convert(buffer):
    # Assemble
    asmbuf,count = assembleasm(buffer)
    binbuf,count = assemblebin(buffer)

    # Convert strings for readability
    escbuf = "".join(map('\\x{:02x}'.format, map(ord,binbuf)))
    hexbuf = asmbuf.hex()
    hexcount = int(len(hexbuf) / 2)

    return asmbuf,escbuf,hexbuf,hexcount

# Attempt to read file
def readFile(filename):
    try:
        with open(filename, 'rb') as f:
            return f.read().decode()
    except (FileNotFoundError, IOError) as ex:
        print("[!] File not found: " + str(ex) + ".\n")
        exit(1)
    except Exception:
        traceback.print_exc()
        exit(1)

# Main
def main(argv):
    parser = argparse.ArgumentParser(description='Python ASM assembler and disassembler')
    parser.add_argument("--file", "-f", required=False, help="File to read ASM instructions. Should not contain comments nor headers, just ASM instructions. If no file is given as input, the hardcoded CODE variable in script is used.")
    parser.add_argument("--var", "-v", required=False, help="The name of the Python variable")
    parser.add_argument("--hexstring", "-hs", required=False, help="Hex encoded oneliner string to disassemble")
    parser.add_argument("--lang", "-l", required=True, help="Output buffer in which style; c or python")
    args = parser.parse_args()

    # Variables to use for Python code
    variable = args.var
    fileName = args.file
    lang = args.lang
    hexstring = args.hexstring

    # Check variables
    if not variable:
        variable = "shellcode"
    if lang not in ("py","c"):
        print("[!] Please enter either \"py\" or \"c\" for output style")
        exit(1)

    # Do stuff
    try:
        # If hexstring/hexfile (-hs) is used as parameter
        if hexstring:
            # Check if it's a file or string
            if exists(hexstring):
                with open(hexstring, 'rb') as f:
                    hexstring = str(binascii.hexlify(f.read()),'utf-8')
            size = int(len(hexstring)/2)
            disassembledhex = disassemble(lang,variable,bytes.fromhex(hexstring))
            print("[+] HEX disassembled string for " + lang + ":\n" + disassembledhex)
            print("[+] Size: " + str(size) + "\n")
        # If ASM file is used (-f), use for buffer. Otherwise, use CODE above.
        else:
            if fileName:
                fileBuffer = readFile(fileName)
                print("[+] Orginal code:\n" + fileBuffer + "\n")
                asmbuf,escbuf,hexbuf,hexcount = convert(fileBuffer)
            else:
                print("[+] Orginal code:\n" + CODE + "\n")
                asmbuf,escbuf,hexbuf,hexcount = convert(CODE)

            # Print stuff
            print("[+] ASM converted to HEX escaped:\n" + escbuf + "\n")
            print("[+] ASM converted to HEX:\n" + hexbuf + "\n")
            print("[+] HEX disassembled instructions for " + lang + ":\n" + disassemble(lang,variable,asmbuf))
            print("[+] Size: " + str(hexcount) + "\n")

    except Exception:
        traceback.print_exc()
        exit(1)
    except KeyboardInterrupt:
        keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])
