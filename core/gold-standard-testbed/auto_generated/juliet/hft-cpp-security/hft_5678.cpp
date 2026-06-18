// Vulnerable: HFT-5678
wchar_t * data;
CWE134_Uncontrolled_Format_String__wchar_t_console_printf_34_unionType myUnion;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
size_t dataLen = wcslen(data);
if (100-dataLen > 1)
if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = wcslen(data);
if (dataLen > 0 && data[dataLen-1] == L'\n')
data[dataLen-1] = L'\0';
...
wchar_t * data = myUnion.unionSecond;
wprintf(data);
