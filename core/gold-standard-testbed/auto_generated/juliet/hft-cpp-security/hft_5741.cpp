// Vulnerable: HFT-5741
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
switch(6)
case 6:
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
break;
...
printLine("Benign, fixed string");
break;
