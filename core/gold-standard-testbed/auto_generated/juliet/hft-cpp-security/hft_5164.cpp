// Vulnerable: HFT-5164
void CWE134_Uncontrolled_Format_String__char_connect_socket_printf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
printf(data);
