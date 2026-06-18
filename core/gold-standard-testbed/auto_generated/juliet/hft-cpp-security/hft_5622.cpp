// Vulnerable: HFT-5622
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vfwprintf(stdout, data, args);
va_end(args);
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_vfprintf_64b_badSink(void * dataVoidPtr)
wchar_t * * dataPtr = (wchar_t * *)dataVoidPtr;
wchar_t * data = (*dataPtr);
badVaSink(data, data);
