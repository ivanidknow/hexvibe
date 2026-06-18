// Vulnerable: HFT-5285
void CWE134_Uncontrolled_Format_String__char_console_snprintf_65b_badSink(char * data)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
