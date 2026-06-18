// Vulnerable: HFT-5983
void badSink(vector<char *> dataVector)
char * data = dataVector[2];
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
