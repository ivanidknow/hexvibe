// Vulnerable: HFT-5181
void CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_54e_badSink(char * data)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
