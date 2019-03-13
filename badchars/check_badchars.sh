#!/bin/bash

BADCHARS="\\x00|\\x0a|\\x0d"

if [ $# -eq 0 ] 
then
	echo "No arguments supplied"
else
    echo '[+] Checking ... '
    objdump -d ./$1 | grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' | egrep -o ${BADCHARS} | uniq
    echo '[+] Done!'
fi
