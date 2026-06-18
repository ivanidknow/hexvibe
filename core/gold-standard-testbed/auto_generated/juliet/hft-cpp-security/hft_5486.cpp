// Vulnerable: HFT-5486
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_61b_badSource(data);
fprintf(stdout, data);
