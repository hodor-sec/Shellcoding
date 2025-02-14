#!/usr/bin/python3
import traceback
import sys
import os
import binascii
import argparse

badchars = None

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

class Helpers:
    def colorBadbytes(originalsc):
        outsclines = []
        outwidth = 20
        lenhex = 4
        
        # Convert badchar bytes to pretty "\x" encoded string
        prettyBadchars = Helpers.convertPrettyHex(badchars)

        # Strip per 4 chars for hex prefixed output
        bclines = [prettyBadchars[i:i + lenhex] for i in range(0, len(prettyBadchars), lenhex)]
        sclines = [originalsc[i:i + lenhex] for i in range(0, len(originalsc), lenhex)]

        # Compare if badchars show up in shellcode and color if so
        # Check and color badchars
        outsclines.append("shellcode = (\n\tb\"")
        sccolor = ""
        for i, char in enumerate(sclines, 1):
            # Add bad char colored red
            if char in bclines:
                colorchar = Colors.RED + char + Colors.END
            else:
                colorchar = char
            
            sccolor += colorchar + ('"\n\tb"' if i % outwidth == 0 else '')

        outsclines.append(sccolor + "\"\n)\n")
        coloredsc = ''.join(outsclines)  

        return coloredsc
        
    def mapBadChars(sh):
        i = 0
        badIndex = []

        while i < len(sh):
            for c in badchars:
                if sh[i] == c:
                    badIndex.append(i)
            i=i+1
        return badIndex

    def mapandconvertShellcode(selectedsc):
        # Color characters for both original bad and encoded chars
        selectedschex = Helpers.convertPrettyHex(selectedsc)
        coloredoriginalsc = Helpers.colorBadbytes(selectedschex)
        print("Original shellcode: \n" + coloredoriginalsc)
        return coloredoriginalsc
    
    def convertPrettyHex(sh):
        """
        DESCR: Prefix each shellcode char with \\x
        IN: Shellcode
        OUT: \\x prefixed shellcode
        """
        # hexencoded = "".join(map('\\x{:02x}'.format, sh))
        hexencoded = "".join(map(lambda x: '\\x{:02x}'.format(x), sh))
        return hexencoded
    
class Badchars:
    def programbadchars(badchars=None):
        i = 0
        programbadChars = []

        for c in badchars:
            programbadChars.append(i)
        return programbadChars
    
    def parseBadchars(badchars_str):
        """ Parse bad characters passed as \x01\x02... into a list of integers. """
        badchars = []
        hexchars = badchars_str.split('\\x')[1:]  # Skip the empty string before the first \x
        for hexchar in hexchars:
            try:
                badchars.append(int(hexchar, 16))
            except ValueError:
                print(f"Invalid hex character: \\x{hexchar}")
        return badchars
    
    def readFile(file_path):
        """ Read binary content from a file. """
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                return f.read()
        else:
            print(f"Error: File {file_path} not found!")
            sys.exit(1)
    
class Shellcode:
    def asmcalcShellcode():
        # Source from: https://github.com/peterferrie/win-exec-calc-shellcode/tree/master
        # Compiled using;
        # $ nasm -f win32 -o win-exec-calc-shellcode.o win-exec-calc-shellcode.asm
        # $ ld -m i386pe -o win-exec-calc-shellcode.bin win-exec-calc-shellcode.o
        # Payload size: 127 bytes
        shellcode = (
                b"\x31\xc0"                        # 0x0         xor  eax, eax
                b"\x50"                            # 0x2         push eax
                b"\x68\x63\x61\x6c\x63"            # 0x3         push 0x636c6163
                b"\x54"                            # 0x8         push esp
                b"\x59"                            # 0x9         pop  ecx
                b"\x50"                            # 0x10        push eax
                b"\x40"                            # 0x11        inc  eax
                b"\x92"                            # 0x12        xchg eax, edx
                b"\x74\x15"                        # 0x13        je   0x24
                b"\x51"                            # 0x15        push ecx
                b"\x64\x8b\x72\x2f"                # 0x16        mov  esi, dword ptr fs:[edx + 0x2f]
                b"\x8b\x76\x0c"                    # 0x20        mov  esi, dword ptr [esi + 0xc]
                b"\x8b\x76\x0c"                    # 0x23        mov  esi, dword ptr [esi + 0xc]
                b"\xad"                            # 0x26        lodsdeax, dword ptr [esi]
                b"\x8b\x30"                        # 0x27        mov  esi, dword ptr [eax]
                b"\x8b\x7e\x18"                    # 0x29        mov  edi, dword ptr [esi + 0x18]
                b"\xb2\x50"                        # 0x32        mov  dl, 0x50
                b"\xeb\x1a"                        # 0x34        jmp  0x3e
                b"\xb2\x60"                        # 0x36        mov  dl, 0x60
                b"\x48"                            # 0x38        dec  eax
                b"\x29\xd4"                        # 0x39        sub  esp, edx
                b"\x65\x48"                        # 0x41        dec  eax
                b"\x8b\x32"                        # 0x43        mov  esi, dword ptr [edx]
                b"\x48"                            # 0x45        dec  eax
                b"\x8b\x76\x18"                    # 0x46        mov  esi, dword ptr [esi + 0x18]
                b"\x48"                            # 0x49        dec  eax
                b"\x8b\x76\x10"                    # 0x50        mov  esi, dword ptr [esi + 0x10]
                b"\x48"                            # 0x53        dec  eax
                b"\xad"                            # 0x54        lodsdeax, dword ptr [esi]
                b"\x48"                            # 0x55        dec  eax
                b"\x8b\x30"                        # 0x56        mov  esi, dword ptr [eax]
                b"\x48"                            # 0x58        dec  eax
                b"\x8b\x7e\x30"                    # 0x59        mov  edi, dword ptr [esi + 0x30]
                b"\x03\x57\x3c"                    # 0x62        add  edx, dword ptr [edi + 0x3c]
                b"\x8b\x5c\x17\x28"                # 0x65        mov  ebx, dword ptr [edi + edx + 0x28]
                b"\x8b\x74\x1f\x20"                # 0x69        mov  esi, dword ptr [edi + ebx + 0x20]
                b"\x48"                            # 0x73        dec  eax
                b"\x01\xfe"                        # 0x74        add  esi, edi
                b"\x8b\x54\x1f\x24"                # 0x76        mov  edx, dword ptr [edi + ebx + 0x24]
                b"\x0f\xb7\x2c\x17"                # 0x80        movzxebp, word ptr [edi + edx]
                b"\x8d\x52\x02"                    # 0x84        lea  edx, [edx + 2]
                b"\xad"                            # 0x87        lodsdeax, dword ptr [esi]
                b"\x81\x3c\x07\x57\x69\x6e\x45"    # 0x88        cmp  dword ptr [edi + eax], 0x456e6957
                b"\x75\xef"                        # 0x95        jne  0x50
                b"\x8b\x74\x1f\x1c"                # 0x97        mov  esi, dword ptr [edi + ebx + 0x1c]
                b"\x48"                            # 0x101       dec  eax
                b"\x01\xfe"                        # 0x102       add  esi, edi
                b"\x8b\x34\xae"                    # 0x104       mov  esi, dword ptr [esi + ebp*4]
                b"\x48"                            # 0x107       dec  eax
                b"\x01\xf7"                        # 0x108       add  edi, esi
                b"\x99"                            # 0x110       cdq
                b"\xff\xd7"                        # 0x111       call edi
                b"\xff"                            # 0x113       db   0xff
                b"\xff"                            # 0x114       db   0xff
                b"\xff"                            # 0x115       db   0xff
                b"\xff\x00"                        # 0x116       inc  dword ptr [eax]
                b"\x00\x00"                        # 0x118       add  byte ptr [eax], al
                b"\xff"                            # 0x120       db   0xff
                b"\xff"                            # 0x121       db   0xff
                b"\xff"                            # 0x122       db   0xff
                b"\xff\x00"                        # 0x123       inc  dword ptr [eax]
                b"\x00\x00"                        # 0x125       add  byte ptr [eax], al
        )
        return shellcode
    
    def encodedShellcode():
        shellcode = b""
        return shellcode

    def encodedShellcodeHex():
        shellcode = b""
        return shellcode

    def mappedbadscchars():
        badchars = b""
        return badchars

    def markedbadscchars():
        markedchars = []
        return markedchars

# Main
def main(argv):
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="A script to check payloads for badbytes and pretty color if found.")  
    # Required positional arguments (e.g., for host and port)
    parser.add_argument("--file", "-f", type=str, default=None, help="The payload or file to check for badbytes")
    parser.add_argument("--badchars", "-b", type=str, default=None, help="The payload or file to check for badbytes (Example: \"\\x0a\\x0d\")")
    parser.add_argument("--hexstr", "-hs", type=str, default=None, help="The hexstring to check for badbytes as argument (Example: fc4883e4f0e8cc)")
    # Parse the arguments
    args = parser.parse_args()
    
    # Globals
    global badchars
    
    # Set Badchars
    if args.badchars:
        badchars = Badchars.parseBadchars(args.badchars)
        Badchars.programbadchars(badchars)
    else:
        # Default badchars
        badchars = [0x00, 0x0a, 0x0d]

    # Process file input
    if args.file:
        file_data = Badchars.readFile(args.file)
        selectedsc = file_data
    
    # Process hex string
    if args.hexstr:
        hexstr_data = bytes.fromhex(args.hexstr)
        selectedsc = hexstr_data
    
    if args.file is None and args.hexstr is None:
        parser.print_help()
        sys.exit(0)
    
    try:
        # Map badchars and convert shellcode
        Helpers.mapandconvertShellcode(selectedsc)
        
    except Exception:
        traceback.print_exc()
        sys.exit(0)

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])
