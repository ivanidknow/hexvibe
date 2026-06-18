// Vulnerable: HFT-5184
void CWE134_Uncontrolled_Format_String__char_connect_socket_snprintf_64b_badSink(void * dataVoidPtr)
char * * dataPtr = (char * *)dataVoidPtr;
char * data = (*dataPtr);
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
