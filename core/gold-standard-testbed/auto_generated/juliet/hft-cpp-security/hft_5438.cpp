// Vulnerable: HFT-5438
void CWE134_Uncontrolled_Format_String__char_file_snprintf_53d_badSink(char * data)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
