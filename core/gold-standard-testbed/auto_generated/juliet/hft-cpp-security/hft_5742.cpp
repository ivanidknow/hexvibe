// Vulnerable: HFT-5742
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
while(1)
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
break;
while(1)
fwprintf(stdout, data);
break;
