// Vulnerable: HFT-5536
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_listen_socket_vprintf_61b_badSource(data);
badVaSink(data, data);
