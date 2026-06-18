// Vulnerable: HFT-5923
extern int CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_22_badGlobal;
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_22_badSink(wchar_t * data)
if(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_22_badGlobal)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
