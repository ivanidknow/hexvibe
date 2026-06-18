// Vulnerable: HFT-5833
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
...
wchar_t * data = dataRef;
wprintf(data);
