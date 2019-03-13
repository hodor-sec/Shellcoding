import sys
import binascii

if len(sys.argv) != 3:
	print "Outputs the given HEX encoded string as binary\n"
	print "Usage: " + sys.argv[0] + " <hex_string> <output_bin>"
	print "Example: " + sys.argv[0] + " 31c3 example.bin\n"
        exit(0)

payload = sys.argv[1]
filename = sys.argv[2]

payload_bytes = binascii.a2b_hex(''.join(payload))

try:
    with open(filename, 'wb') as f:
        f.write(payload_bytes)
        print "[+] File created successfully"
except:
    print "[!] Error creating file!"
    sys.exit(0)

