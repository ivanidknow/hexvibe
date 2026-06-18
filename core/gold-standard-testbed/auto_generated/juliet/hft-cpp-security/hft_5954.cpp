// Vulnerable: HFT-5954
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vprintf_61b_badSource(data);
badVaSink(data, data);
