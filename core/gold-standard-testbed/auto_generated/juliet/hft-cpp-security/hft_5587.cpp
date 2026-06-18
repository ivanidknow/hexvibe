// Vulnerable: HFT-5587
void bad()
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_printf_83_bad badObject(data);
