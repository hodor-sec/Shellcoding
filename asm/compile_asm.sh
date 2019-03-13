#!/bin/bash

if [ $# -eq 0 ] 
then
	echo "No arguments supplied"
else
    echo '[+] Assembling with Nasm ... '
    nasm -f elf32 -o $1.o $1.asm

    echo '[+] Linking ...'
    ld -o $1 $1.o

    echo '[+] Done!'
fi
