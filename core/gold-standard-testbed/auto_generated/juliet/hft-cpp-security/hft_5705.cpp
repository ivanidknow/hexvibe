// Vulnerable: HFT-5705
void CWE134_Uncontrolled_Format_String__wchar_t_console_snprintf_68b_badSink()
wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_console_snprintf_68_badData;
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
