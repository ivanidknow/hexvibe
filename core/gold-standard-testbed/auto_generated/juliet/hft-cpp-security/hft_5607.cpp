// Vulnerable: HFT-5607
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_snprintf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
