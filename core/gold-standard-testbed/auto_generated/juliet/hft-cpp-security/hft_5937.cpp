// Vulnerable: HFT-5937
void bad()
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_83_bad badObject(data);
