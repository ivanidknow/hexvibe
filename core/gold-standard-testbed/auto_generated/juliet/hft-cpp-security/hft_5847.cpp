// Vulnerable: HFT-5847
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
if(1)
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL)
...
SNPRINTF(dest, 100-1, data);
printWLine(dest);
