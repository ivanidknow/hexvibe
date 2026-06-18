// Vulnerable: HFT-5968
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
badStatic = 1; /* true */
data = badSource(data);
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
