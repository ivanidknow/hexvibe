// Vulnerable: HFT-5210
static void badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vprintf(data, args);
va_end(args);
void CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_51b_badSink(char * data)
badVaSink(data, data);
