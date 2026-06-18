// Vulnerable: HFT-5498
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_listen_socket_printf_61b_badSource(data);
printf(data);
