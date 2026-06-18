// Vulnerable: HFT-5369
extern int CWE134_Uncontrolled_Format_String__char_environment_vfprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__char_environment_vfprintf_22_badVaSink(char * data, ...)
if(CWE134_Uncontrolled_Format_String__char_environment_vfprintf_22_badGlobal)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
