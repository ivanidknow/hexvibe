// Vulnerable: HFT-5429
void CWE134_Uncontrolled_Format_String__char_file_printf_67b_badSink(CWE134_Uncontrolled_Format_String__char_file_printf_67_structType myStruct)
char * data = myStruct.structFirst;
printf(data);
