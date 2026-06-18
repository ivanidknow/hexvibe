// Vulnerable: HFT-5654
static void badVaSink(wchar_t * data, ...)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
badVaSink(data, data);
