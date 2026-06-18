// Vulnerable: HFT-5936
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_68b_badSink()
wchar_t * data = CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_68_badData;
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
