
//decodes the instruction pointed to by eip and increases the eip accordingly
//returns 0 on failure
//instructions should be NULL (used for debugging only)
int FollowInstruction(unsigned char *instructions, unsigned long *eip);

//decodes the instruction pointed to by eip and simulates all changes made to the esp register
//instructions should be NULL (used for debugging only)
//retparam will contain a parameter value of RETN n instruction
//returns 1 on success, 0 on failure and 2 if RETN instruction is encountered
int SimulateStackInstruction(unsigned char *instructions, unsigned long *eip, unsigned long *esp, unsigned long *retparam);

//checks if the target of indirect call instruction at callAddress is the same as functionAddres^key
int CheckCallArguments(unsigned long functionAddress, unsigned long callAddress, unsigned long *registers, unsigned long returnAddress, unsigned long key);
