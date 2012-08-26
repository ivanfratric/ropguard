// ropguard.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <windows.h>
#include <stdio.h>
#include "createprocess.h"
#include "ropsettings.h"

#pragma warning(disable : 4996)

//prints the usage information
void PrintUsage() {
	printf("Usage: ropguard <PID>\n");
	printf("       ropguard \"<command>\"\n");
}

//returns true if string is numeric
bool IsNumeric(char *str) {
	int i, n = strlen(str);
	for(i=0;i<n;i++) {
		if((str[i]<'0')||(str[i]>'9')) return false;
	}
	return true;
}

extern ROPSettings *ropSettings;

//main program
int _tmain(int argc, _TCHAR* argv[])
{
	if(argc<2) {
		PrintUsage();
		return 0;
	}

	//get the full path of ropguarddll.dll
	char dllpath[1000];
	char *filename;
	if(!GetModuleFileName(NULL, dllpath, 980)) {
		printf("Error: could not obtain current executable path\n");
		return 0;
	}
	filename = strrchr(dllpath,'\\');
	if(!filename) {
		printf("Error: could not obtain current executable path\n");
		return 0;
	}
	filename++;
	strcpy(filename, "ropsettings.txt");
	ropSettings = new ROPSettings();
	ReadROPSettings(dllpath);
	strcpy(filename, "ropguarddll.dll");


	//if the first argument is a number it's considered to be a PID
	if(IsNumeric(argv[1])) {
		//protect existing process
		GuardExistingProcess(atol(argv[1]), dllpath);
	} else {
		//create new protected process
		if(GetROPSettings()->waitEntryPoint) {
			CreateNewGuardedProcess(argv[1], dllpath, true);
		} else {
			CreateNewGuardedProcess(argv[1], dllpath, false);
		}
	}

	return 0;
}

