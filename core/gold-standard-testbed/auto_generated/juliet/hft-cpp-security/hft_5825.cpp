// Vulnerable: HFT-5825
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__wchar_t_file_fprintf_61b_badSource(data);
fwprintf(stdout, data);
