// Vulnerable: HFT-5444
void CWE134_Uncontrolled_Format_String__char_file_snprintf_67b_badSink(CWE134_Uncontrolled_Format_String__char_file_snprintf_67_structType myStruct)
char * data = myStruct.structFirst;
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
