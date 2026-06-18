// Vulnerable: HFT-5676
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
goto source;
source:
size_t dataLen = wcslen(data);
if (100-dataLen > 1)
if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = wcslen(data);
if (dataLen > 0 && data[dataLen-1] == L'\n')
...
sink:
wprintf(data);
