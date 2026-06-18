// Vulnerable: HFT-5621
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_vfprintf_61b_badSource(data);
badVaSink(data, data);
