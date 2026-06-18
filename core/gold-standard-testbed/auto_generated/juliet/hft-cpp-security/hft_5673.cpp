// Vulnerable: HFT-5673
void CWE134_Uncontrolled_Format_String__wchar_t_console_fprintf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_console_fprintf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
fwprintf(stdout, data);
