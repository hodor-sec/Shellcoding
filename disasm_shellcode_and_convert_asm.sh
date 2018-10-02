Convert to ASM:
ndisasm -u FILE

----------

echo -ne "\x31\xc0\x50\x27\x68\xef\x2f\x2f\x73\x68\xc3\x68\xef\x2f\x62\x69\xc3\x6e\x89\xe3\x50\xef\x89\xe2\x27\x53\x37\x89\xe1\xc3\xb0\x0b\xcd\x80\xc3" | ndisasm -u -

00000000  31C0              xor eax,eax
00000002  50                push eax
00000003  27                daa
00000004  68EF2F2F73        push dword 0x732f2fef
00000009  68C368EF2F        push dword 0x2fef68c3
0000000E  6269C3            bound ebp,[ecx-0x3d]
00000011  6E                outsb
00000012  89E3              mov ebx,esp
00000014  50                push eax
00000015  EF                out dx,eax
00000016  89E2              mov edx,esp
00000018  27                daa
00000019  53                push ebx
0000001A  37                aaa
0000001B  89E1              mov ecx,esp
0000001D  C3                ret
0000001E  B00B              mov al,0xb
00000020  CD80              int 0x80
00000022  C3                ret

------------

awk '{$1=$2=""; print $0}' > disasm_file
