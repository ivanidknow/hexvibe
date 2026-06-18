// Vulnerable: HFT-5546
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_listen_socket_w32_vsnprintf_61b_badSource(data);
badVaSink(data, data);
