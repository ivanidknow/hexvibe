// Vulnerable: HFT-5709
wchar_t * data;
wchar_t * *dataPtr1 = &data;
wchar_t * *dataPtr2 = &data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
wchar_t * data = *dataPtr1;
size_t dataLen = wcslen(data);
if (100-dataLen > 1)
if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = wcslen(data);
...
wchar_t * data = *dataPtr2;
badVaSink(data, data);
