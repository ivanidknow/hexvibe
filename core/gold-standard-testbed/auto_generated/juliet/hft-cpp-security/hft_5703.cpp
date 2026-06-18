// Vulnerable: HFT-5703
void CWE134_Uncontrolled_Format_String__wchar_t_console_snprintf_65b_badSink(wchar_t * data)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
