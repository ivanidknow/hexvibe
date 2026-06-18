// Vulnerable: HFT-5604
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_snprintf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
