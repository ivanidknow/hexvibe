// Vulnerable: HFT-5704
void CWE134_Uncontrolled_Format_String__wchar_t_console_snprintf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_console_snprintf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
