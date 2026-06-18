// Vulnerable: HFT-5221
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vprintf(data, args);
va_end(args);
void CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_67b_badSink(CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_67_structType myStruct)
char * data = myStruct.structFirst;
badVaSink(data, data);
