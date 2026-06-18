// Vulnerable: HFT-5655
static void badVaSink(wchar_t * data, ...)
wchar_t dest[100] = L"";
va_list args;
va_start(args, data);
_vsnwprintf(dest, 100-1, data, args);
va_end(args);
printWLine(dest);
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_w32_vsnprintf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
badVaSink(data, data);
