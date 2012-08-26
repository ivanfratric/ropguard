#include <windows.h>

#include "ropsettings.h"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
using namespace std;

#pragma warning(disable : 4996)

//contains ROPGuard's configuration
ROPSettings *ropSettings;

//returns the ropSettings object
ROPSettings *GetROPSettings() {
	return ropSettings;
}

int GetNumGuardedFunctions() {
	//return sizeof(guardedFunctions)/sizeof(ROPGuardedFunction);
	return ropSettings->GetNumGuardedFunctions();
}

ROPGuardedFunction *GetGuardedFunctions() {
	//return guardedFunctions;
	return ropSettings->GetGuardedFunctions();
}

//adds a critical function
//moduleName : name of the module that contains the critical function
//functionName : name of the critical function
//stackIncrement : how many DWORDS does function take from the stack (-1 if don't know)
//protect : if true, ROPCheck will be called whenever the function is called
//clearCache : if true, when this function gets called, executable module cache will be cleared
void ROPSettings::AddFunction(const char *moduleName, const char *functionName, int stackIncrement, bool protect, bool clearCache) {
	for(int i=0;i<numGuardedFunctions;i++) {
		if((strcmp(guardedFunctions[i].moduleName, moduleName)==0)&&(strcmp(guardedFunctions[i].functionName, functionName)==0)) {
			if(protect) {
				guardedFunctions[i].stackIncrement = stackIncrement;
				guardedFunctions[i].criticalFunction = true;
			}
			if(clearCache) {
				guardedFunctions[i].clearCache = true;
			}
			return;
		}
	}

	guardedFunctions = (ROPGuardedFunction *)realloc(guardedFunctions, (numGuardedFunctions + 1)*sizeof(ROPGuardedFunction));
	strncpy(guardedFunctions[numGuardedFunctions].moduleName, moduleName, 31);
	strncpy(guardedFunctions[numGuardedFunctions].functionName, functionName, 63);
	guardedFunctions[numGuardedFunctions].originalAddress = 0;
	guardedFunctions[numGuardedFunctions].patchedAddress = 0;
	guardedFunctions[numGuardedFunctions].criticalFunction = protect;
	guardedFunctions[numGuardedFunctions].clearCache = clearCache;
	guardedFunctions[numGuardedFunctions].stackIncrement = stackIncrement;
	numGuardedFunctions++;
}

//converts string to int
int ParseInt(string &s) {
	int result;
	stringstream convert(s);
	if (!(convert >> result)) result = 0;
	return result;
}

//converts string to boolean value
bool ParseBool(string &s) {
	if(s == "true") return true;
	return false;
}

//erases spaces from the beginning and the end of a string
void trim(string &s) {
	s.erase(0,s.find_first_not_of(" \n\r\t"));
	s.erase(s.find_last_not_of(" \n\r\t")+1);
}

//parse settings file
int ReadROPSettings(char *filename) {
	string line, varname, varvalue, errorreport;
	int pos;
	ifstream settingsfile (filename);
	if (!settingsfile.is_open()) {
		MessageBoxA(NULL, "Could not read settings file, protection will NOT be enabled", "ROPGuard", MB_OK);
		return 0;
	}

	while (settingsfile.good()) {
		getline (settingsfile,line);

		if(line.length() == 0) continue;

		if(line[0] == '#') continue; //skip comments

		pos = line.find_first_of('=');
		if(pos == -1) continue;

		varname = line.substr(0,pos);
		varvalue = line.substr(pos+1);
		trim(varname);
		trim(varvalue);

		if(varname == "ShowMessageBoxOnLoaded") ropSettings->showMessageBoxOnLoaded = ParseBool(varvalue);
		else if(varname == "WaitEntryPoint") ropSettings->waitEntryPoint = ParseBool(varvalue);
		else if(varname == "ExecutableModuleCache") ropSettings->executableModuleCache = ParseBool(varvalue);
		else if(varname == "CheckFunctionAddressOnStack") ropSettings->checkFunctionAddressOnStack = ParseBool(varvalue);
		else if(varname == "CheckStackPointer") ropSettings->checkStackPointer = ParseBool(varvalue);
		else if(varname == "CheckReturnAddress") ropSettings->checkReturnAddress = ParseBool(varvalue);
		else if(varname == "CheckCallTarget") ropSettings->checkCallTarget = ParseBool(varvalue);
		else if(varname == "AllowIndirectCFCalls") ropSettings->allowIndirectCFCalls  = ParseBool(varvalue);
		else if(varname == "AllowFarCFCalls") ropSettings->allowFarCFCalls = ParseBool(varvalue);
		else if(varname == "CheckStackFrames") ropSettings->checkStackFrames = ParseBool(varvalue);
		else if(varname == "RequireFramePointers") ropSettings->requireFramePointers = ParseBool(varvalue);
		else if(varname == "SimulateProgramFlow") ropSettings->simulateProgramFlow = ParseBool(varvalue);
		else if(varname == "PreserveStack") ropSettings->preserveStack = ParseInt(varvalue);
		else if(varname == "MaxStackFrames") ropSettings->maxStackFrames = ParseInt(varvalue);
		else if(varname == "MaxInstructionsToSimulate") ropSettings->maxInstructionsToSimulate = ParseInt(varvalue);
		else if(varname == "GuardChildProcesses") ropSettings->guardChildProcesses = ParseBool(varvalue);
		else if(varname == "PreventLoadLibraryFromSMB") ropSettings->preventLoadLibraryFromSMB = ParseBool(varvalue);
		else if(varname == "PreventVirtualProtectOnStack") ropSettings->preventVirtualProtectOnStack = ParseBool(varvalue);
		else if((varname == "ProtectFunction")||(varname == "ClearCache")) {
			string moduleName, functionName;
			int stackIncrement = -1;
			bool protect = false;
			bool cache = false;

			pos = varvalue.find_first_of(':');
			if(pos == -1) {
				errorreport = "Error parsing line in the configuration file: " + line;
				MessageBoxA(NULL, errorreport.c_str(), "ROPGuard", MB_OK);
				continue;
			}

			moduleName = varvalue.substr(0,pos);
			functionName = varvalue.substr(pos+1);
			trim(moduleName);
			trim(functionName);

			pos = functionName.find_first_of(':');
			if(pos>=0) {
				string stackIncrementStr;
				stackIncrementStr = functionName.substr(pos+1);
				functionName.erase(pos);
				trim(functionName);
				trim(stackIncrementStr);
				stackIncrement = ParseInt(stackIncrementStr);
			}

			if(moduleName.length() > 31) {
				MessageBoxA(NULL, "Error parsing configuration file: Module name must have less than 32 characters", "ROPGuard", MB_OK);
				continue;
			}

			if(functionName.length() > 63) {
				MessageBoxA(NULL, "Error parsing configuration file: Function name must have less than 64 characters", "ROPGuard", MB_OK);
				continue;
			}

			if(varname == "ProtectFunction") protect = true;
			if(varname == "ClearCache") cache = true;
			ropSettings->AddFunction(moduleName.c_str(), functionName.c_str(), stackIncrement, protect, cache);
		} else {
			errorreport = "Error parsing line in the configuration file: " + line;
			MessageBoxA(NULL, errorreport.c_str(), "ROPGuard", MB_OK);
			continue;
		}
	}

	settingsfile.close();
	return 1;
}

//read ropsettings.txt file in the same folder as ropguarddll.dll
int ReadROPSettings() {
	//create ROPSettings object
	ropSettings = new ROPSettings();

	//get the path of the ropguard dll
	char fullpath[1000];
	char *filename;
	HMODULE dllhandle;
	dllhandle = GetModuleHandle("ropguarddll.dll");
	if((!dllhandle) || (!GetModuleFileName(dllhandle, fullpath, 999))) {
		MessageBoxA(NULL, "Warning: could not obtain ropguarddll path", "ROPGuard", MB_OK);
		return 0;
	}

	filename = strrchr(fullpath,'\\');

	if(!filename) {
		MessageBoxA(NULL, "Warning: could not obtain ropsettings path", "ROPGuard", MB_OK);
		return 0;
	}

	filename++;

	strcpy(filename, "ropsettings.txt");

	return ReadROPSettings(fullpath);
}

