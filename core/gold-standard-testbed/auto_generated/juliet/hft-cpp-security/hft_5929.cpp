// Vulnerable: HFT-5929
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_53d_badSink(wchar_t * data)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
