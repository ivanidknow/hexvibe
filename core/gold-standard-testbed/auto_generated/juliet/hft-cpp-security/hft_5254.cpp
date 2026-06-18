// Vulnerable: HFT-5254
void CWE134_Uncontrolled_Format_String__char_console_fprintf_67b_badSink(CWE134_Uncontrolled_Format_String__char_console_fprintf_67_structType myStruct)
char * data = myStruct.structFirst;
fprintf(stdout, data);
