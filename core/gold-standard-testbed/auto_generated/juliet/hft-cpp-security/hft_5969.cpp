// Vulnerable: HFT-5969
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badGlobal = 1; /* true */
data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badSource(data);
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
