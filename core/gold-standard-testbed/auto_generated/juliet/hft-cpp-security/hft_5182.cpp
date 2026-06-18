// Vulnerable: HFT-5182
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_61b_badSource(data);
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
