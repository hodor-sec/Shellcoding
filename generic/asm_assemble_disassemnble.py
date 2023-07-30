import binascii
import traceback
import argparse
import sys
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
def disassemble(var,asmbuf):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    disasmbuf = var + " = {\n"
    for i in md.disasm(asmbuf, 0x00):
        opcode = "b\"\\x" + "\\x".join("{:02x}".format(c) for c in i.bytes) + "\""
        disasmbuf += f"\t{opcode:<25}# "
        disasmbuf += f"0x{i.address:<10}"
        disasmbuf += f"{i.mnemonic:<5}"
        disasmbuf += f"{i.op_str:<10}\n"
    disasmbuf += "}\n"
    return disasmbuf

# Main
def main(argv):
    parser = argparse.ArgumentParser(description='Python assembler and disassembler')
    parser.add_argument("--var", "-v", required=True, help="The name of the Python variable")
    args = parser.parse_args()

    # Variable to use for Python code
    variable = args.var

    # Do stuff
    try:
        # Call functions
        asmbuf,count = assembleasm(CODE)
        binbuf,count = assemblebin(CODE)

        # Convert strings for readability
        escbuf = "".join(map('\\x{:02x}'.format, map(ord,binbuf)))
        hexbuf = asmbuf.hex()

        # Print stuff
        print("[+] HEX escaped buffer:\n" + escbuf + "\n")
        print("[+] HEX buffer:\n" + hexbuf + "\n")
        print("[+] Disassembled instructions for Python:\n" + disassemble(variable,asmbuf))
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    except KeyboardInterrupt:
        keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])
