// Vulnerable: HFT-5586
void badSink(map<int, wchar_t *> dataMap)
wchar_t * data = dataMap[2];
wprintf(data);
