import ctypes, struct
from keystone import *

CODE = (
"    start:                                ;"
)

# Initialize engine in X86-32bit mode
try:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    print("Encoded %d instructions..." % count)

    opcodes = ""
    for dec in encoding:
        opcodes += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    print("size: %d " % len(encoding))
    print("payload = (\"" + opcodes + "\")")

    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    shellcode = bytearray(sh)

    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                            ctypes.c_int(len(shellcode)),
                                            ctypes.c_int(0x3000),
                                            ctypes.c_int(0x40))

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                        buf,
                                        ctypes.c_int(len(shellcode)))

    print("Shellcode located at address %s" % hex(ptr))

    input("...ENTER TO EXECUTE SHELLCODE...")
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.c_int(ptr),
                                            ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.pointer(ctypes.c_int(0)))

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

except KsError as e:
    print("ERROR: %s" %e)

