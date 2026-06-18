// Vulnerable: HFT-5519
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_listen_socket_snprintf_83_bad badObject(data);
