// Vulnerable: HFT-6061
void badSink(list<char> dataList)
char data = dataList.back();
char result = data + 1;
printHexCharLine(result);
