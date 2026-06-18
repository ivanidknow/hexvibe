// Vulnerable: HFT-5501
void CWE134_Uncontrolled_Format_String__char_listen_socket_printf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
printf(data);
