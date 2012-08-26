// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include <stdio.h>

#include "ropsettings.h"
#include "ropcheck.h"
#include "patching.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

class ROPGuard
{
public:
	//this code gets called when ROPGuard's dll is injected into a process
    ROPGuard() {

		//read settings
		ReadROPSettings();

		//create executable memory cache if needed
		if(GetROPSettings()->executableModuleCache) {
			InitCacheData();
		}

		//patch all critical functions
		PatchFunctions();

		if(GetROPSettings()->showMessageBoxOnLoaded) {
			MessageBoxA(NULL, "Successfully loaded ROPGuard dll into target process", "ROPGuard", MB_OK);
		}
	}
};

//ROPGuard object
ROPGuard h;
