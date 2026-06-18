// Vulnerable: HFT-5938
extern int CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_badVaSink(wchar_t * data, ...)
if(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_badGlobal)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
