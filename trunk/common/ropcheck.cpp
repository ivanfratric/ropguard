#include <stdio.h>
#include <windows.h>

#include "ropsettings.h"
#include "x86opcodes.h"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
using namespace std;
#include "ropcheck.h"
#include <vector>

//--------------------------------------------------------------------------
//contains a beginning and an end address of an executable part of memory
struct ExecutableModule
{
  unsigned long start;
  unsigned long end;
};

//--------------------------------------------------------------------------
// executable memory cache
vector<ExecutableModule> *executableModules;
CRITICAL_SECTION cacheMutex;

//--------------------------------------------------------------------------
// creates the executable memory cache and a mutex which guards it
void InitCacheData()
{
  executableModules = new vector<ExecutableModule>;
  InitializeCriticalSection(&cacheMutex);
}

//--------------------------------------------------------------------------
// Shows a message box to the user informing him of possible attack
// The user can either terminate the process or continue the execution normally
void ReportPossibleROP(string &report)
{
  string messageboxtext;
  messageboxtext = "ROPGuard has detected a possible threat.\n"
                    "Press OK to terminate the current process.\n"
                    "Press Cancel or ESC key to continue the execution normally\n\n"
                    "Problem details:\n" + report;

  if(MessageBoxA(NULL, messageboxtext.c_str(), "ROPGuard", MB_OKCANCEL) == IDOK)
  {
    exit(0);
  }
}

//--------------------------------------------------------------------------
// Gets the top and bottom address of the stack
void GetStackInfo(unsigned long *stackBottom, unsigned long *stackTop)
{
  char *TIB    = (char *) __readfsdword(0x18);
  *stackTop    = *((unsigned long *)(TIB+4));
  *stackBottom = *((unsigned long *)(TIB+8));
}

//--------------------------------------------------------------------------
//checks if a memory address is executable
int IsAddressExecutable(LPCVOID address)
{
  bool cache = GetROPSettings()->executableModuleCache;

  if (cache)
  {
    EnterCriticalSection(&cacheMutex);
    for (unsigned int i=0; i<executableModules->size(); i++)
    {
      ExecutableModule &em = (*executableModules)[i];
      if ((((unsigned long)address)>=em.start)&&(((unsigned long)address)<em.end))
      {
        LeaveCriticalSection(&cacheMutex);
        return 1;
      }
    }
    LeaveCriticalSection(&cacheMutex);
  }

  MEMORY_BASIC_INFORMATION info = {0};
  if (!VirtualQuery(address, &info, sizeof(info)))
    return 0;

  if ((info.Protect & EXEC_PROTECTION) != 0)
  {
    if (cache)
    {
      ExecutableModule newmodule;
      newmodule.start = (unsigned long)(info.BaseAddress);
      newmodule.end = (unsigned long)(info.BaseAddress) + (unsigned long)(info.RegionSize);
      EnterCriticalSection(&cacheMutex);
      executableModules->push_back(newmodule);
      LeaveCriticalSection(&cacheMutex);
    }
    return 1;
  }

  return 0;
}

//--------------------------------------------------------------------------
// checks if the instruction preceding the one pointed by address is a call instruction
int PrecededByCall(unsigned char *address)
{
  int i;

  // check for call opcodes
  if (*(address-5) == 0xE8)
    return 1;

  if (*(address-3) == 0xE8)
    return 1;

  if(*(address-5) == 0x9A)
    return 1;

  if (*(address-7) == 0x9A)
    return 1;

  // FF opcode
  for (i=2;i<8;i++)
  {
    if ((*(address-i) == 0xFF) && (((*(address-i+1))&0x38)==0x10))
      return 1;
  }

  for (i=2;i<10;i++)
  {
    if ((*(address-i) == 0xFF) && (((*(address-i+1))&0x38)==0x18))
      return 1;
  }

  return 0;
}

//--------------------------------------------------------------------------
// checks if the instruction preceding the one pointed by address is a call instruction
// unlike PrecededByCall, this function can disallow dome forms of call
int CFPrecededByCall(unsigned char *address)
{
  int i;

  //check for call opcodes
  if (*(address-5) == 0xE8)
    return 1;

  if (*(address-3) == 0xE8)
    return 1;

  if (GetROPSettings()->allowFarCFCalls)
  {
    if (*(address-5) == 0x9A)
      return 1;
    if (*(address-7) == 0x9A)
      return 1;
  }

  // FF opcode
  if(GetROPSettings()->allowIndirectCFCalls)
  {
    for(i=2;i<8;i++)
    {
      if((*(address-i) == 0xFF) && (((*(address-i+1))&0x38)==0x10))
        return 1;
    }

    if(GetROPSettings()->allowFarCFCalls)
    {
      for(i=2;i<10;i++)
      {
        if((*(address-i) == 0xFF) && (((*(address-i+1))&0x38)==0x18))
          return 1;
      }
    }
  }

  return 0;
}

//--------------------------------------------------------------------------
//checks if the target of the call instruction preceding returnAddress is the same as cfAddress^ADDR_SCRAMBLE_KEY
int CheckCallTarget(
  unsigned char *returnAddress,
  unsigned long *registers, unsigned long cfAddress)
{
  int i;

  // direct call
  unsigned long callAddress;
  if (*(returnAddress-5) == 0xE8)
  {
    callAddress = (long)(returnAddress) + *((long *)(returnAddress-4));
    if(callAddress == (cfAddress^ADDR_SCRAMBLE_KEY))
      return 1;

    if (IsAddressExecutable((LPCVOID)callAddress))
    {
      if((*((unsigned char *)(callAddress)) == 0xFF)&&(*((unsigned char *)(callAddress+1)) == 0x25))
      {
        callAddress = *((unsigned long *)(callAddress+2));
        callAddress = *((unsigned long *)(callAddress));
        if(callAddress == (cfAddress^ADDR_SCRAMBLE_KEY))
          return 1;
      }
    }
  }

  if (*(returnAddress-3) == 0xE8)
  {
    callAddress = (long)(returnAddress) + *((short *)(returnAddress-2));
    if(callAddress == (cfAddress^ADDR_SCRAMBLE_KEY))
      return 1;

    if (IsAddressExecutable((LPCVOID)callAddress))
    {
      if ((*((unsigned char *)(callAddress)) == 0xFF) && (*((unsigned char *)(callAddress+1)) == 0x25))
      {
        callAddress = *((unsigned long *)(callAddress+2));
        callAddress = *((unsigned long *)(callAddress));
        if(callAddress == (cfAddress^ADDR_SCRAMBLE_KEY))
          return 1;
      }
    }
  }

  // direct far call
  if(GetROPSettings()->allowFarCFCalls)
  {
    if(*(returnAddress-5) == 0x9A)
      return 1;
    if(*(returnAddress-7) == 0x9A)
      return 1;
  }

  // indirect call
  if (GetROPSettings()->allowIndirectCFCalls)
  {
    for(i=2;i<8;i++)
    {
      if (CheckCallArguments(cfAddress, (unsigned long)(returnAddress-i), registers, (unsigned long)(returnAddress), ADDR_SCRAMBLE_KEY) == 1)
      {
        return 1;
      }
    }

    //indirect far call
    if(GetROPSettings()->allowFarCFCalls)
    {
      for (i=2;i<10;i++)
      {
        if ((*(returnAddress-i) == 0xFF) && (((*(returnAddress-i+1))&0x38)==0x18))
          return 1;
      }
    }
  }

  return 0;
}

//--------------------------------------------------------------------------
// Performs checks on the return address of the critical function
int CFCheckReturnAddress(DWORD returnAddress, DWORD functionAddress, DWORD *registers)
{
  // Is return address executable?
  if (!IsAddressExecutable((LPCVOID)returnAddress))
  {
    stringstream errorreport;
    errorreport << "Return address is not executable.\nReturn address: ";
    errorreport << std::hex << returnAddress;
    ReportPossibleROP(errorreport.str());
    return 0;
  }

  // is return address preceded by call?
  if (!CFPrecededByCall((unsigned char *)returnAddress))
  {
    stringstream errorreport;
    errorreport << "Return address not preceded by call.\nReturn address: ";
    errorreport << std::hex << returnAddress;
    ReportPossibleROP(errorreport.str());
    return 0;
  }

  // is the target of call instruction preceeding the return address the same as the address of critical function?
  if (    (GetROPSettings()->checkCallTarget)
      &&  (!CheckCallTarget((unsigned char *)returnAddress, registers, functionAddress)))
  {
    stringstream errorreport;
    errorreport << "Call target is not the same as the function address.\nReturn address: ";
    errorreport << std::hex << returnAddress;
    ReportPossibleROP(errorreport.str());
    return 0;
  }
  return 1;
}

//--------------------------------------------------------------------------
// performs checks on the return address of any function
int CheckReturnAddress(DWORD returnAddress)
{
  //is return address executable?
  if (!IsAddressExecutable((LPCVOID)returnAddress))
  {
    stringstream errorreport;
    errorreport << "Return address is not executable.\n"
                   "Return address: ";
    errorreport << std::hex << returnAddress;
    ReportPossibleROP(errorreport.str());
    return 0;
  }

  // is return address preceded by call?
  if (!PrecededByCall((unsigned char *)returnAddress))
  {
    stringstream errorreport;
    errorreport << "Return address not preceded by call.\n"
                   "Return address: ";
    errorreport << std::hex << returnAddress;
    ReportPossibleROP(errorreport.str());
    return 0;
  }
  return 1;
}

//--------------------------------------------------------------------------
// performs the checks on the stack frames below the frame of the critical function
int CheckStackFrames(DWORD *stackPtr, DWORD *framePtr)
{
  DWORD *returnAddress;
  DWORD *newFramePtr;
  DWORD *originalFramePtr;

  unsigned long stackBottom, stackTop;
  GetStackInfo(&stackBottom, &stackTop);

  originalFramePtr = framePtr;

  //frame pointer must point to the stack
  if (((unsigned long)framePtr<stackBottom)||((unsigned long)framePtr>stackTop))
  {
    if (GetROPSettings()->requireFramePointers)
    {
      stringstream errorreport;
      errorreport << "Return address not preceded by call. Frame pointer:\n";
      errorreport << std::hex << (unsigned long)framePtr;
      ReportPossibleROP(errorreport.str());
      return 0;
    }
    else
    {
      return 1;
    }
  }

  // frame pointer must be "below" the stack pointer
  if (((unsigned long)framePtr)<((unsigned long)stackPtr))
  {
    stringstream errorreport;
    errorreport << "Frame pointer is above stack pointer on stack";
    errorreport << " Stack pointer:  " << std::hex << (unsigned long)stackPtr;
    errorreport << " Frame pointer: " << std::hex << (unsigned long)framePtr;
    ReportPossibleROP(errorreport.str());
    return 0;
  }

  for (unsigned int i=0; i<GetROPSettings()->maxStackFrames; i++)
  {
    newFramePtr = (DWORD *)(*(framePtr));
    returnAddress = (DWORD *)(*(framePtr+1));

    if(!returnAddress)
      break;

    // is return address executable?
    if (!IsAddressExecutable(returnAddress))
    {
      stringstream errorreport;
      errorreport << "Return address is not executable.";
      errorreport << " Return address: " << std::hex << (unsigned long)returnAddress;
      errorreport << " Frame pointer: " << std::hex << (unsigned long)framePtr;
      errorreport << " Original frame pointer: " << std::hex << (unsigned long)originalFramePtr;
      ReportPossibleROP(errorreport.str());
      return 0;
    }

    // is return address preceded by call?
    if(!PrecededByCall((unsigned char *)returnAddress))
    {
      stringstream errorreport;
      errorreport << "Return address not preceded by call.";
      errorreport << " Return address: " << std::hex << (unsigned long)returnAddress;
      errorreport << " Frame pointer: " << std::hex << (unsigned long)framePtr;
      errorreport << " Original frame pointer: " << std::hex << (unsigned long)originalFramePtr;
      ReportPossibleROP(errorreport.str());
      return 0;
    }

    // is the new frame pointer on stack?
    if (((unsigned long)newFramePtr<stackBottom)||((unsigned long)newFramePtr>stackTop))
    {
      if(GetROPSettings()->requireFramePointers)
      {
        stringstream errorreport;
        errorreport << "Frame pointer is outside of stack.";
        errorreport << " Frame pointer: " << std::hex << (unsigned long)framePtr;
        errorreport << " Original frame pointer: " << std::hex << (unsigned long)originalFramePtr;
        ReportPossibleROP(errorreport.str());
        return 0;
      }
      else
      {
        return 1;
      }
    }

    //is the new frame pointer "below" the old one?
    if((unsigned long)newFramePtr <= (unsigned long)framePtr) {
      if(GetROPSettings()->requireFramePointers) {
        stringstream errorreport;
        errorreport << "Next frame pointer is not below the previous one on stack.";
        errorreport << " Frame pointer: " << std::hex << (unsigned long)framePtr;
        errorreport << " Original frame pointer: " << std::hex << (unsigned long)originalFramePtr;
        ReportPossibleROP(errorreport.str());
        return 0;
      } else {
        return 1;
      }
    }

    framePtr = newFramePtr;
  }

  return 1;
}

//--------------------------------------------------------------------------
//check if the current stack pointer is in a valid location, as indicated by thread information block
int CheckStackPointer(unsigned long stackPtr)
{
  unsigned long stackBottom, stackTop;
  GetStackInfo(&stackBottom, &stackTop);

  if ((stackPtr<stackBottom)||(stackPtr>stackTop))
  {
    stringstream errorreport;
    errorreport << "Stack pointer is outside of stack. Stack address:\n";
    errorreport << std::hex << stackPtr;
    ReportPossibleROP(errorreport.str());
    return 0;
  }

  return 1;
}

//--------------------------------------------------------------------------
// checks if the address of protected function is on the stack just above the current return address
// if it is, this could mean that we "returned into" the beginning of critical function instead of calling it
int CheckFunctionAddressOnStack(
      unsigned long functionAddress,
      unsigned long *stack)
{
  int i,n;
  n = (GetROPSettings()->preserveStack)/sizeof(unsigned long);

  for (i=0;i<n;i++)
  {
    if ((stack[i]^ADDR_SCRAMBLE_KEY) == functionAddress)
    {
      stringstream errorreport;
      errorreport << "Address of critical function found on stack. Stack address:\n";
      errorreport << std::hex << (unsigned long)stack << ", Function address: " << (functionAddress^ADDR_SCRAMBLE_KEY);
      ReportPossibleROP(errorreport.str());
      return 0;
    }
  }
  return 1;
}

//--------------------------------------------------------------------------
// simulates a number of instructions after the return from the critical function
// tracks changes to stack pointer and for any encountered RETN performs appropriate check
int SimulateProgramFlow(unsigned long stackPtr, unsigned long stackIncrement)
{
  unsigned long returnAddress;
  unsigned long eip;

  //MessageBoxA(NULL, "Inside SimulateProgramFlow", "ROPGuard", MB_OK);

  int n = GetROPSettings()->maxInstructionsToSimulate;

  returnAddress = *((unsigned long *)stackPtr);
  stackPtr += stackIncrement + 4;

  eip = returnAddress;
  for (int i=0; i<n; i++)
  {
    //printf("%x %x\n",eip,stackPtr); getch();
    int simret = SimulateStackInstruction(NULL, &eip, &stackPtr, &stackIncrement);
    if (simret == 0)
      break;

    // we reached RETN instruction, check the return address
    if (simret == 2)
    {
      returnAddress = *((unsigned long *)stackPtr);
      if (!CheckReturnAddress(returnAddress))
        return 0;

      stackPtr += stackIncrement+4;
      eip = returnAddress;
    }
  }

  //MessageBoxA(NULL, "OK", "ROPGuard", MB_OK);

  return 1;
}

//--------------------------------------------------------------------------
// indicates that the checks should be performed
bool protectionEnabled;

//--------------------------------------------------------------------------
// the main function that performs the check, called in the prologue of every critical function
// functionAddress - the original address of the critical function, used to determine what function are we in
// registers - an array containing the register values in the moment of critical function call
void __stdcall ROPCheck(
      unsigned long functionAddress,
      unsigned long *registers)
{
  // still initializing protection
  if (!protectionEnabled)
    return;

  unsigned long framePointer, stackPointer;
  framePointer = registers[2];
  stackPointer = registers[3];

  //MessageBoxA(NULL, "Inside ROPCheck", "ROPGuard", MB_OK);

  // Identify the function that is being called
  int i, numFunctions = GetNumGuardedFunctions();
  ROPGuardedFunction *guardedFunctions = GetGuardedFunctions();
  ROPGuardedFunction *currentFunction = NULL;
  for (i=0;i<numFunctions;i++)
  {
    if (guardedFunctions[i].originalAddress == functionAddress)
    {
      currentFunction = &(guardedFunctions[i]);
      break;
    }
  }

  if (currentFunction == NULL)
  {
    MessageBoxA(
      NULL,
      "Inside ROPCheck, but guarded function not identified",
      "ROPGuard",
      MB_OK);
    return;
  }

  if (GetROPSettings()->executableModuleCache)
  {
    if (currentFunction->clearCache)
    {
      EnterCriticalSection(&cacheMutex);
      executableModules->clear();
      LeaveCriticalSection(&cacheMutex);
    }
    if (!currentFunction->criticalFunction)
      return;
  }

  /*
  if(strcmp(currentFunction->functionName,"CreateProcessInternalW")==0)
  {
    MessageBoxA(NULL, "Creating new process", "ROPGuard", MB_OK);
  }
  */

  if (GetROPSettings()->checkFunctionAddressOnStack)
  {
    if (!CheckFunctionAddressOnStack(
            functionAddress,
            (unsigned long *)stackPointer))
    {
      return;
    }
  }

  // Check if ESP is in the thread's original stack space (defined in the TIB)
  if (GetROPSettings()->checkStackPointer)
  {
    if (!CheckStackPointer(stackPointer + GetROPSettings()->preserveStack))
      return;
  }

  // Check if return address is proceeded by a call (to the target)
  if (GetROPSettings()->checkReturnAddress)
  {
    DWORD returnAddress = *((DWORD *)(stackPointer + GetROPSettings()->preserveStack));
    if (!CFCheckReturnAddress(returnAddress, functionAddress, registers))
      return;
  }

  // Check stack frames
  if (GetROPSettings()->checkStackFrames)
  {
    if (!CheckStackFrames(
      (DWORD *)(stackPointer + GetROPSettings()->preserveStack),
      (DWORD *)framePointer))
    {
      return;
    }
  }

  // Simulate program flow
  if ((GetROPSettings()->simulateProgramFlow) && (currentFunction->stackIncrement>=0))
  {
    SimulateProgramFlow(
        stackPointer + GetROPSettings()->preserveStack,
        currentFunction->stackIncrement * 4);
  }

  //
  // function-specific protections
  //

  // prevent loading a library over SMB
  if (    (GetROPSettings()->preventLoadLibraryFromSMB)
       && (strcmp(currentFunction->functionName, "LoadLibraryExW")==0))
  {
    char *dllname = (char *)(*((DWORD *)(stackPointer + GetROPSettings()->preserveStack + 4)));
    if ((dllname[0] == '\\')&&(dllname[2] == '\\'))
    {
      if (!((dllname[4] == '?') && (dllname[6] == '\\')))
      {
        stringstream errorreport;
        errorreport << "Program attempted to load a DLL over SMB\n";
        errorreport << "Stack pointer: " << std::hex << stackPointer << "\n";
        errorreport << "Function address: " << std::hex << (functionAddress^ADDR_SCRAMBLE_KEY) << "\n";

        int dllnamesize = wcslen((LPCWSTR)dllname);
        char * dllname2 = new char[dllnamesize+1];
        WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)dllname, dllnamesize, dllname2, dllnamesize, NULL, NULL);
        dllname2[dllnamesize] = 0;
        errorreport << "Library name: " << dllname2;
        delete [] dllname2;

        ReportPossibleROP(errorreport.str());
        return;
      }
    }
  }

  // prevent changing access rights of stack
  if (GetROPSettings()->preventVirtualProtectOnStack) do
  {
    DWORD address;
    if (strcmp(currentFunction->functionName,"VirtualProtect")==0)
      address = *((DWORD *)(stackPointer + GetROPSettings()->preserveStack + 4));
    else if (strcmp(currentFunction->functionName, "VirtualProtectEx")==0)
      address = address = *((DWORD *)(stackPointer + GetROPSettings()->preserveStack + 8));
    else
      break;

    DWORD stackBottom, stackTop;
    GetStackInfo(&stackBottom, &stackTop);
    if ((address>=stackBottom) && (address<stackTop))
    {
      stringstream errorreport;
      errorreport << "Program attempted to change access rights of stack\n";
      errorreport << "Stack pointer: " << std::hex << stackPointer << "\n";
      errorreport << "Function address: " << std::hex << (functionAddress^ADDR_SCRAMBLE_KEY);
      ReportPossibleROP(errorreport.str());
      return;
    }
  } while (false);
}
