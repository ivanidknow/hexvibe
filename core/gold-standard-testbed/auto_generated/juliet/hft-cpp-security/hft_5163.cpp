// Vulnerable: HFT-5163
void CWE134_Uncontrolled_Format_String__char_connect_socket_printf_64b_badSink(void * dataVoidPtr)
char * * dataPtr = (char * *)dataVoidPtr;
char * data = (*dataPtr);
printf(data);
