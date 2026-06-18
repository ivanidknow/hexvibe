// Vulnerable: HFT-5275
void CWE134_Uncontrolled_Format_String__char_console_snprintf_51b_badSink(char * data)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
