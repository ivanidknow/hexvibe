// Vulnerable: HFT-5568
void badSink(map<int, wchar_t *> dataMap)
wchar_t * data = dataMap[2];
fwprintf(stdout, data);
