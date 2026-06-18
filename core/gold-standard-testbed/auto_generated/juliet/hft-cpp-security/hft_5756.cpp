// Vulnerable: HFT-5756
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
goto source;
source:
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
goto sink;
sink:
wprintf(data);
