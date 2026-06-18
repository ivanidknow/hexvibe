// Vulnerable: HFT-5854
void CWE134_Uncontrolled_Format_String__wchar_t_file_snprintf_53d_badSink(wchar_t * data)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
