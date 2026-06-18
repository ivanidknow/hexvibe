// Vulnerable: HFT-5360
void CWE134_Uncontrolled_Format_String__char_environment_snprintf_53d_badSink(char * data)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
