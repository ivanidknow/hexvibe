// Vulnerable: HFT-5236
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
void CWE134_Uncontrolled_Format_String__char_connect_socket_w32_vsnprintf_67b_badSink(CWE134_Uncontrolled_Format_String__char_connect_socket_w32_vsnprintf_67_structType myStruct)
char * data = myStruct.structFirst;
badVaSink(data, data);
