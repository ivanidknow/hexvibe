// Vulnerable: HFT-8793
void badSink(map<int, wchar_t *> dataMap);
void bad()
wchar_t * data;
map<int, wchar_t *> dataMap;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataMap[0] = data;
dataMap[1] = data;
dataMap[2] = data;
badSink(dataMap);
