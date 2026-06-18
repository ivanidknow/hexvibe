// Vulnerable: HFT-5662
static void badSource(wchar_t * &data)
size_t dataLen = wcslen(data);
if (100-dataLen > 1)
if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = wcslen(data);
if (dataLen > 0 && data[dataLen-1] == L'\n')
data[dataLen-1] = L'\0';
else
printLine("fgetws() failed");
data[dataLen] = L'\0';
...
badSource(data);
fwprintf(stdout, data);
