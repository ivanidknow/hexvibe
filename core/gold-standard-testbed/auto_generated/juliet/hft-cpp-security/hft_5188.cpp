// Vulnerable: HFT-5188
void CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_68b_badSink()
char * data = CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_68_badData;
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
