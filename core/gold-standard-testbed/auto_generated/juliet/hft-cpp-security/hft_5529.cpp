// Vulnerable: HFT-5529
extern int CWE134_Uncontrolled_Format_String__char_listen_socket_vprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__char_listen_socket_vprintf_22_badVaSink(char * data, ...)
if(CWE134_Uncontrolled_Format_String__char_listen_socket_vprintf_22_badGlobal)
va_list args;
va_start(args, data);
vprintf(data, args);
va_end(args);
