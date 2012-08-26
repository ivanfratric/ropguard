#include <stdio.h>
#include <windows.h>

#include "ropsettings.h"
#include "x86opcodes.h"
#include "ropcheck.h"
#include "createprocess.h"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
using namespace std;

//patch a critical function, replacing its prologue with the jump to patch prologue that calls ROPCheck
//moduleName : name of the module that contains the critical function
//functionName : name of the critical function
//originalAddress : here the original address of critical function will be stored
//patchcode : a pointer to executable memory that will contain the patched function prologue
int PatchFunction(char *moduleName, char *functionName, unsigned long *originalAddress, unsigned char *patchcode) {
	unsigned long functionAddress, patchHeaderEnd;
	unsigned int i;
	DWORD oldProtect, newProtect;

	//get the address of function to be patched
	functionAddress = (unsigned long)GetProcAddress(GetModuleHandle(moduleName), functionName);
	if(!functionAddress) {
		stringstream errorreport;
		errorreport << "Warning: Could not get address of " << moduleName << ":" << functionName;
		MessageBoxA(NULL, errorreport.str().c_str(), "ROPGuard", MB_OK);
		return 0;
	}

	//don't patch same function twice
	unsigned int numFunctions = GetNumGuardedFunctions();
	ROPGuardedFunction *guardedFunctions = GetGuardedFunctions();
	for(i=0;i<numFunctions;i++) {
		if(guardedFunctions[i].originalAddress == (functionAddress^ADDR_SCRAMBLE_KEY)) return 0;
	}


	//char buf[1000];
	//sprintf(buf, "Address of %s : 0x%x",functionName,functionAddress);
    //MessageBoxA(NULL, buf, "ROPGuard", MB_OK);

	*originalAddress = functionAddress;

	patchHeaderEnd = functionAddress;

	while((patchHeaderEnd-functionAddress)<5) {
		if(!FollowInstruction(NULL, &patchHeaderEnd)) {
			stringstream errorreport;
			errorreport << "Warning: Could not determine function header of " << moduleName << ":" << functionName;
			MessageBoxA(NULL, errorreport.str().c_str(), "ROPGuard", MB_OK);
			return 0;			
		}
	}

	unsigned char *patchcode2 = (unsigned char *)(functionAddress);

	patchcode[0] = 0x81; //SUB ESP, PRESERVE_STACK
	patchcode[1] = 0xEC;
	*((unsigned long *)(&(patchcode[2]))) = GetROPSettings()->preserveStack; 
	patchcode[6] = 0x60; //PUSHAD
	patchcode[7] = 0x54; //PUSH ESP
	patchcode[8] = 0x68; //PUSH functionAddress
	*((unsigned long *)(&(patchcode[9]))) = functionAddress^ADDR_SCRAMBLE_KEY; //scramble functionAddress so that it wouldn't confuse ropcheck later
	patchcode[13] = 0xE8; //CALL ROPCheck
	*((unsigned long *)(&(patchcode[14]))) = (unsigned long)(&ROPCheck) - (unsigned long)(&(patchcode[18]));
	patchcode[18] = 0x81; //ADD ESP, PRESERVE_STACK + space taken by PUSHAD
	patchcode[19] = 0xC4;
	*((unsigned long *)(&(patchcode[20]))) = (GetROPSettings()->preserveStack + 8*4);

	if((strcmp(functionName,"CreateProcessInternalW")!=0) || (!GetROPSettings()->guardChildProcesses)) {
		for(i=0;i<patchHeaderEnd-functionAddress;i++) { //instructions from the header of function being patched
			patchcode[24+i] = patchcode2[i];
		}
		patchcode[24+i] = 0xE9; //jmp patchHeaderEnd
		*((unsigned long *)(&(patchcode[25+i]))) = patchHeaderEnd - (unsigned long)(&(patchcode[29+i]));
	} else {
		patchcode[24] = 0xE9; //jmp CreateProcessInternalGuarded
		*((unsigned long *)(&(patchcode[25]))) = (unsigned long)(&CreateProcessInternalGuarded) - (unsigned long)(&(patchcode[29]));

		for(i=0;i<patchHeaderEnd-functionAddress;i++) { //instructions from the header of function being patched
			patchcode[50+i] = patchcode2[i];
		}
		patchcode[50+i] = 0xE9; //jmp patchHeaderEnd
		*((unsigned long *)(&(patchcode[51+i]))) = patchHeaderEnd - (unsigned long)(&(patchcode[55+i]));

		SetCreateProcessInternalOriginalPtr((unsigned long)(&(patchcode[50])));
	}

	//change access rights so we can patch the dll
	VirtualProtect((LPVOID)functionAddress,patchHeaderEnd-functionAddress,PAGE_EXECUTE_READWRITE,&oldProtect);

	patchcode2[0] = 0xE9; //jmp patchcode
	*((unsigned long *)(&(patchcode2[1]))) = (unsigned long)(patchcode) - (unsigned long)(&(patchcode2[5]));
	for(i=5;i<(patchHeaderEnd-functionAddress);i++) {
		patchcode2[i] = 0x90;
	}

	//sprintf(buf, "%s.%s patched successfully",moduleName,functionName);
	//MessageBoxA(NULL, buf, "ROPGuard", MB_OK);

	//return old access rights
	VirtualProtect((LPVOID)functionAddress,patchHeaderEnd-functionAddress,oldProtect,&newProtect);

	return 1;
}

extern bool protectionEnabled;

//patches all critical functions as defined in the configuration
int PatchFunctions() {
	//disable protection while we patch functions
	protectionEnabled = false;

	int i;
	int ret;
	int numFunctions = GetNumGuardedFunctions();
	ROPGuardedFunction *guardedFunctions = GetGuardedFunctions();
	DWORD oldProtect;

	unsigned char *patchcode;
	int patchcodesize = numFunctions*100;
	int patchsizeused = 0;

	//allocate memory for the extra code that will be used in patching the functions
	patchcode = (unsigned char *)VirtualAlloc(NULL, patchcodesize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!patchcode) return 0;

	//patch every function
	for(i=0;i<numFunctions;i++) {

		//don't patch functions that just clear the executable cache if cache is not enabled
		if((!GetROPSettings()->executableModuleCache)&&(!guardedFunctions[i].criticalFunction)) continue;

		//patch function
		ret = PatchFunction(guardedFunctions[i].moduleName, 
			guardedFunctions[i].functionName,
			&(guardedFunctions[i].originalAddress),
			&(patchcode[patchsizeused]));
		if(ret) {
			guardedFunctions[i].originalAddress = guardedFunctions[i].originalAddress^ADDR_SCRAMBLE_KEY;
			guardedFunctions[i].patchedAddress = (unsigned long)(&(patchcode[patchsizeused]));
			patchsizeused += 100;
		} else {
			guardedFunctions[i].originalAddress = 0;
		}
	}

	//protect the patch code from writing
	VirtualProtect(patchcode, patchcodesize, PAGE_EXECUTE_READ, &oldProtect);

	//enable protection
	protectionEnabled = true;

	return 1;
};
