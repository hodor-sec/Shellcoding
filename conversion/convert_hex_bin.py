import sys
import binascii

if len(sys.argv) != 3:
    print("Outputs the given HEX encoded string as binary\n")
    print("Usage: " + sys.argv[0] + " <hex_string> <output_bin>")
    print("Example: " + sys.argv[0] + " \"31c3\" example.bin")
    print("Example: " + sys.argv[0] + " \"\\x31\\xc3\" example.bin\n")
    exit(0)

payload = sys.argv[1]
filename = sys.argv[2]

if payload.find("x") != -1:
    payload = payload.replace("\\x", "")
payload_bytes = binascii.a2b_hex(''.join(payload))

try:
    with open(filename, 'wb') as f:
        f.write(payload_bytes)
        print("[+] File created successfully")
except:
    print("[!] Error creating file!")
    sys.exit(0)

