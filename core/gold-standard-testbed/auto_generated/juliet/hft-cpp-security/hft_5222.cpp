// Vulnerable: HFT-5222
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_83_bad badObject(data);
