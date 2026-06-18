// Vulnerable: HFT-5831
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
goto source;
source:
size_t dataLen = wcslen(data);
FILE * pFile;
if (100-dataLen > 1)
pFile = fopen(FILENAME, "r");
if (pFile != NULL)
...
sink:
wprintf(data);
