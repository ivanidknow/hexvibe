// Vulnerable: HFT-5830
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
if(globalReturnsTrueOrFalse())
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL)
...
else
wprintf(L"%s\n", data);
