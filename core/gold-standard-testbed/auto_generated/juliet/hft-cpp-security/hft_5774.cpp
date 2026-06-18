// Vulnerable: HFT-5774
void CWE134_Uncontrolled_Format_String__wchar_t_environment_snprintf_52c_badSink(wchar_t * data)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
