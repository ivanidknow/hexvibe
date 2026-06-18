// Vulnerable: HFT-5769
void bad()
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__wchar_t_environment_printf_83_bad badObject(data);
