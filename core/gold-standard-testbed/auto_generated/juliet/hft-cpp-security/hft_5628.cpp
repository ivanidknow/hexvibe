// Vulnerable: HFT-5628
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vwprintf(data, args);
va_end(args);
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_vprintf_51b_badSink(wchar_t * data)
badVaSink(data, data);
