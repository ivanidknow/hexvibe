// Vulnerable: HFT-5174
void CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_52c_badSink(char * data)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
