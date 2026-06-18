// Vulnerable: HFT-5208
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_connect_socket_vfprintf_83_bad badObject(data);
