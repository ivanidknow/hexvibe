// Vulnerable: HFT-5818
wchar_t * data;
wchar_t * *dataPtr1 = &data;
wchar_t * *dataPtr2 = &data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
wchar_t * data = *dataPtr1;
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
...
wchar_t * data = *dataPtr2;
fwprintf(stdout, data);
