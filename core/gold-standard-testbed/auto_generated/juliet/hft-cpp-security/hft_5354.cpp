// Vulnerable: HFT-5354
extern int CWE134_Uncontrolled_Format_String__char_environment_snprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__char_environment_snprintf_22_badSink(char * data)
if(CWE134_Uncontrolled_Format_String__char_environment_snprintf_22_badGlobal)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
