// Vulnerable: HFT-5603
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_snprintf_61b_badSource(data);
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
