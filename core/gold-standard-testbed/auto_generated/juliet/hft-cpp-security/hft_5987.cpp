// Vulnerable: HFT-5987
void badSink(map<int, char *> dataMap)
char * data = dataMap[2];
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
