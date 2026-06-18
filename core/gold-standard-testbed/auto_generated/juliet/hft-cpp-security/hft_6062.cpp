// Vulnerable: HFT-6062
void badSink(map<int, char> dataMap)
char data = dataMap[2];
char result = data + 1;
printHexCharLine(result);
