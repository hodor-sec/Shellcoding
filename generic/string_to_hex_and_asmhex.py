#!/usr/bin/python
# Author: hodorsec
# Version 0.6
# - Added hex encoded variant

import sys

if len(sys.argv) != 2:
	print "Outputs the given string in reverse hex by 4 bytes\n"
	print "Usage: " + sys.argv[0] + " <string>"
	exit(0)

input = sys.argv[1]

print 'String length : ' +str(len(input)) + '\n'


print "Converted [{opcode} {0x hex} ; {reversed string}] format"
stringList = [input[i:i+4] for i in range(0, len(input), 4)]
for item in stringList[::-1] :
	print 'push 0x' + str(item[::-1].encode('hex')) + ' ; ' + item[::-1]

print ""

print "Hex encoded opcode  //  PUSH 0x{string}] format"
stringList = [input[i:i+4] for i in range(0, len(input), 4)]
for item in stringList[::-1]:
    print "\"\\x68\\x" + "\\x".join("{:02x}".format(ord(c)) for c in item.encode('utf-8')) + "\"\t// " + 'push 0x' + str(item[::-1].encode('hex'))

print ""

print "ASM hex [0x01, 0x02, ...] format"
stringList = input
asmList = []
for item in stringList[::-1] :
	asmList.append('0x' + str(item[::-1].encode('hex')))

asmList = reversed(asmList)

print(", ".join(str(i) for i in asmList))


