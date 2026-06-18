// Vulnerable: HFT-5413
void CWE134_Uncontrolled_Format_String__char_file_fprintf_67b_badSink(CWE134_Uncontrolled_Format_String__char_file_fprintf_67_structType myStruct)
char * data = myStruct.structFirst;
fprintf(stdout, data);
