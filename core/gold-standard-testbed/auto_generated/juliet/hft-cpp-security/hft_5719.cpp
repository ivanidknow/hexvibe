// Vulnerable: HFT-5719
extern int CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_22_badVaSink(wchar_t * data, ...)
if(CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_22_badGlobal)
va_list args;
va_start(args, data);
vwprintf(data, args);
va_end(args);
