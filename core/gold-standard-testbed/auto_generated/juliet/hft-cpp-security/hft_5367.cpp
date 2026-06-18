// Vulnerable: HFT-5367
void CWE134_Uncontrolled_Format_String__char_environment_snprintf_68b_badSink()
char * data = CWE134_Uncontrolled_Format_String__char_environment_snprintf_68_badData;
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
