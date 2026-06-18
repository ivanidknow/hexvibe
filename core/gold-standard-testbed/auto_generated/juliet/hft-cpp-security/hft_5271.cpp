// Vulnerable: HFT-5271
void CWE134_Uncontrolled_Format_String__char_console_printf_67b_badSink(CWE134_Uncontrolled_Format_String__char_console_printf_67_structType myStruct)
char * data = myStruct.structFirst;
printf(data);
