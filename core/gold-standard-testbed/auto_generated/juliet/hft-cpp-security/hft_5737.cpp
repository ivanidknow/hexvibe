// Vulnerable: HFT-5737
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__wchar_t_console_w32_vsnprintf_61b_badSource(data);
badVaSink(data, data);
