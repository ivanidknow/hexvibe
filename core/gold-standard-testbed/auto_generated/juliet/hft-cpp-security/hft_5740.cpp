// Vulnerable: HFT-5740
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
if(globalReturnsTrueOrFalse())
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
else
wcscpy(data, L"fixedstringtest");
...
else
fwprintf(stdout, L"%s\n", data);
