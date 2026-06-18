// Vulnerable: HFT-6060
void badSink(vector<char> dataVector)
char data = dataVector[2];
char result = data + 1;
printHexCharLine(result);
