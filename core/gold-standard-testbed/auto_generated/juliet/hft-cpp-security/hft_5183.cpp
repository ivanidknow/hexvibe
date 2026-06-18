// Vulnerable: HFT-5183
void CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
