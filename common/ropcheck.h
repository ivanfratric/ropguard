#define EXEC_PROTECTION (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)


// the main function that performs the check, called in the prologue of every critical function
// functionAddress - the original address of the critical function, used to determine what function are we in
// registers - an array containing the register values in the moment of critical function call
void __stdcall ROPCheck(unsigned long functionAddress, unsigned long *registers);

//creates the executable memory cache and a mutex which guards it
void InitCacheData();
