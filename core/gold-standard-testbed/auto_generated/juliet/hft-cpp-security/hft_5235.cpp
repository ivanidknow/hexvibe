// Vulnerable: HFT-5235
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
void CWE134_Uncontrolled_Format_String__char_connect_socket_w32_vsnprintf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
badVaSink(data, data);
