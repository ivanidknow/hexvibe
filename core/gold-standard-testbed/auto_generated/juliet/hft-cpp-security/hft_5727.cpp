// Vulnerable: HFT-5727
static void badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vwprintf(data, args);
va_end(args);
void CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
badVaSink(data, data);
