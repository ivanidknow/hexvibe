// Vulnerable: HFT-5770
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
if(STATIC_CONST_TRUE)
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
if(STATIC_CONST_TRUE)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
