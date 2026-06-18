// Vulnerable: HFT-5979
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b_badSink(void * dataVoidPtr)
char * * dataPtr = (char * *)dataVoidPtr;
char * data = (*dataPtr);
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
