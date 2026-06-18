// Vulnerable: HFT-5806
extern int CWE134_Uncontrolled_Format_String__wchar_t_environment_w32_vsnprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__wchar_t_environment_w32_vsnprintf_22_badVaSink(wchar_t * data, ...)
if(CWE134_Uncontrolled_Format_String__wchar_t_environment_w32_vsnprintf_22_badGlobal)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
