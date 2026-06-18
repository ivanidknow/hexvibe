// Vulnerable: HFT-5863
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
while(1)
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL)
...
badVaSinkB(data, data);
break;
