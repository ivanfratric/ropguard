#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>

#include "createprocess.h"

//--------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength    OPTIONAL);

pfnNtQueryInformationProcess myNtQueryInformationProcess;

//--------------------------------------------------------------------------
// Load NTDLL Library and get entry address
// for NtQueryInformationProcess
int LoadNTDLLFunctions()
{
  HMODULE hNtDll = LoadLibrary("ntdll.dll");
  if (hNtDll == NULL) 
    return 0;

  myNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
  return myNtQueryInformationProcess == NULL ? 0 : 1;
}

//--------------------------------------------------------------------------
// helper functions and macros for parsing PE headers
#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))
#define OPTHDROFFSET(ptr) ((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)))

LPVOID  WINAPI GetModuleEntryPoint(
  LPVOID    lpFile)
{
  PIMAGE_OPTIONAL_HEADER   poh;
  poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET (lpFile);
  return poh == NULL ? NULL :(LPVOID)poh->AddressOfEntryPoint;
}

//--------------------------------------------------------------------------
//returns the entry point of the main module of the process proc
DWORD GetEntryPoint(HANDLE proc)
{
  NTSTATUS ntret;
  PROCESS_BASIC_INFORMATION pbi;
  DWORD imagebase;
  DWORD enrypoint;

  //load NtQueryInformationProcess
  if(!LoadNTDLLFunctions())
    return 0;

  //get peb address
  ntret = (*myNtQueryInformationProcess)(proc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
  if (ntret!=0)
    return 0;
  
  // get base address of module
  if (!ReadProcessMemory(proc, (LPCVOID)((DWORD)(pbi.PebBaseAddress) + 8),&imagebase, sizeof(imagebase), NULL))
    return 0;

  //read PE header
  unsigned char *pe = new unsigned char[4096]; //whole memory page should be quite enough
  if (!ReadProcessMemory(proc, (LPCVOID)(imagebase),pe, 4096, NULL))
  {
    delete [] pe;
    return 0;
  }

  enrypoint = imagebase + (DWORD)(GetModuleEntryPoint((LPVOID)pe));
  delete [] pe;

  return enrypoint;
}

//--------------------------------------------------------------------------
// patches the entry point of the main thread to go into infinite loop
// dll is injected when this loop is reached,
// after which the old entry point data is restored
int PatchEntryPoint(HANDLE proc, HANDLE thread, char *dllName)
{
  DWORD entryPoint;
  DWORD oldProtect1,oldProtect2;
  unsigned char oldHeader[2];
  unsigned char newHeader[2];
  CONTEXT context;

  entryPoint = GetEntryPoint(proc);

  if (!entryPoint)
  {
    printf("Error getting entry point\n");
    return 0;
  }

  // make entry point writeable
  VirtualProtectEx(proc, (LPVOID)entryPoint, 2, PAGE_EXECUTE_READWRITE, &oldProtect1);

  //store 2 bytes from entry point
  if (!ReadProcessMemory(proc, (LPCVOID)(entryPoint),oldHeader, 2, NULL))
  {
    printf("Error reading data from entry point");
    return 0;
  }

  // JMP -2
  newHeader[0] = 0xEB;
  newHeader[1] = 0xFE;

  // patch entry point to go into infinite loop
  if (!WriteProcessMemory(proc, (LPVOID)(entryPoint),newHeader, 2, NULL))
  {
    printf("Error writing to entry point");
    return 0;
  }

  ResumeThread(thread);

  // wait until entry point is reached
  while (true)
  {
    Sleep(100);

    context.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(thread, &context);

    if (context.Eip == entryPoint)
      break;
  }

  InjectDLL(proc, dllName);

  SuspendThread(thread);

  // return original code to entry point
  if (!WriteProcessMemory(proc, (LPVOID)(entryPoint),oldHeader, 2, NULL))
  {
    printf("Error writing to entry point");
    return 0;
  }

  // restore protection
  VirtualProtectEx(proc, (LPVOID)entryPoint, 2, oldProtect1, &oldProtect2);

  return 1;
}
