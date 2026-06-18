// Vulnerable: HFT-5985
void badSink(list<char *> dataList)
char * data = dataList.back();
if (!SetComputerNameA(data))
printLine("Failure setting computer name");
exit(1);
