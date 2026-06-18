// Vulnerable: HFT-5203
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vfprintf(stdout, data, args);
va_end(args);
void CWE134_Uncontrolled_Format_String__char_connect_socket_vfprintf_64b_badSink(void * dataVoidPtr)
char * * dataPtr = (char * *)dataVoidPtr;
char * data = (*dataPtr);
badVaSink(data, data);
