#define ADDR_SCRAMBLE_KEY 0x55555555

//stores information about a critical function
struct ROPGuardedFunction {
	char moduleName[32];  //name of the module in which the function is implemented
	char functionName[64]; //name of the critical function to guard
	unsigned long originalAddress; //original address of the function in the module
	unsigned long patchedAddress; //address of the corresponding guarded function;
	int stackIncrement;
	bool criticalFunction;
	bool clearCache;
};

//contains ROPGuard's configuration
class ROPSettings {
public:
	ROPSettings() {
		waitEntryPoint = true;

		showMessageBoxOnLoaded = true;

		executableModuleCache = true;

		checkFunctionAddressOnStack = true;
		preserveStack = 4;
		checkStackPointer = true;
		checkReturnAddress = true;
		checkCallTarget = false;
		allowIndirectCFCalls = true;
		allowFarCFCalls = true;
		checkStackFrames = false;
		maxStackFrames = 10;
		simulateProgramFlow = true;
		maxInstructionsToSimulate = 10;

		requireFramePointers = false;
		
		guardChildProcesses = true;

		preventLoadLibraryFromSMB = true;
		preventVirtualProtectOnStack = true;

		guardedFunctions = 0;
		numGuardedFunctions = 0;
	}

	//see example configuration file for explanation of different options
	bool showMessageBoxOnLoaded;
	bool executableModuleCache;

	bool checkFunctionAddressOnStack;
	unsigned long preserveStack;
	bool checkStackPointer;
	bool checkReturnAddress;
	bool checkCallTarget;
	bool allowIndirectCFCalls;
	bool allowFarCFCalls;
	bool checkStackFrames;
	bool requireFramePointers;
	unsigned long maxStackFrames;
	bool simulateProgramFlow;
	unsigned long maxInstructionsToSimulate;

	bool guardChildProcesses;
	bool preventLoadLibraryFromSMB;
	bool preventVirtualProtectOnStack;

	bool waitEntryPoint;

	ROPGuardedFunction *GetGuardedFunctions() { return guardedFunctions; }
	int GetNumGuardedFunctions() { return numGuardedFunctions; }

	//adds a critical function
	//moduleName : name of the module that contains the critical function
	//functionName : name of the critical function
	//stackIncrement : how many DWORDS does function take from the stack (-1 if don't know)
	//protect : if true, ROPCheck will be called whenever the function is called
	//clearCache : if true, when this function gets called, executable module cache will be cleared
	void AddFunction(const char *moduleName, const char *functionName, int stackIncrement, bool protect, bool clearCache);
private:
	ROPGuardedFunction *guardedFunctions;
	int numGuardedFunctions;
};

//reads and parses the settings file
int ReadROPSettings(char *filename);

//reads the settings from 'ropsettings.txt' file in the same folder as the loaded 'ropguarddll.dll'
int ReadROPSettings();

//returns the number of critical functions
int GetNumGuardedFunctions();

//returns the pointer to the array of ROPGuardedFunction objects that contain information about critical functions
ROPGuardedFunction *GetGuardedFunctions();

//returns the ropSettings object
ROPSettings *GetROPSettings();
