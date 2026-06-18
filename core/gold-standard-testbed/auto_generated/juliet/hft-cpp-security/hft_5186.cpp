// Vulnerable: HFT-5186
void CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
