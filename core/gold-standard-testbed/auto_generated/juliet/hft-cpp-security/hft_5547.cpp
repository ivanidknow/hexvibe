// Vulnerable: HFT-5547
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
void CWE134_Uncontrolled_Format_String__char_listen_socket_w32_vsnprintf_68b_badSink()
char * data = CWE134_Uncontrolled_Format_String__char_listen_socket_w32_vsnprintf_68_badData;
badVaSink(data, data);
