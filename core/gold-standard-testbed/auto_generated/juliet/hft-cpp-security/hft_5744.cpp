// Vulnerable: HFT-5744
wchar_t * data;
CWE134_Uncontrolled_Format_String__wchar_t_environment_fprintf_34_unionType myUnion;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
size_t dataLen = wcslen(data);
wchar_t * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
wcsncat(data+dataLen, environment, 100-dataLen-1);
myUnion.unionFirst = data;
wchar_t * data = myUnion.unionSecond;
fwprintf(stdout, data);
