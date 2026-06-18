// Vulnerable: HFT-5972
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b_badSink(char * data)
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
