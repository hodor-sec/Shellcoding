#!/bin/bash

if [ $# -eq 0 ] 
then
	echo "No arguments supplied"
else
    echo '[+] Compiling ... '
    gcc -fno-stack-protector -z execstack -fno-pie -o $1 $1.c
    echo '[+] Done!'
fi
