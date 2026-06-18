// Vulnerable: HFT-5689
void CWE134_Uncontrolled_Format_String__wchar_t_console_printf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_console_printf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
wprintf(data);
