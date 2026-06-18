// Vulnerable: HFT-5933
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_54e_badSink(wchar_t * data)
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
