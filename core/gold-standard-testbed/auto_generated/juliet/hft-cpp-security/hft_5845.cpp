// Vulnerable: HFT-5845
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_file_printf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
wprintf(data);
