// Vulnerable: HFT-5488
void CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
fprintf(stdout, data);
