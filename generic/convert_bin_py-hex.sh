#!/bin/sh

if [ $# -eq 1 ]; then
	objdump -D -m i386 -M intel -b binary ./$1 | tail -n +8 | sed 's/^.*[0-9a-f]:\t/ /' | sed 's/[0-9a-f]\{2\} /\\x&/g' | sed 's/ \\x/\\x/g' | sed 's/^/\"/g' | awk '{print $1"\"\t\t# " $2 " " $3 " " $4 " " $5}' | column -t
        else echo "Give a binary program as argument."
fi
