// Vulnerable: HFT-5638
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_vprintf_65b_badVaSink(wchar_t * data, ...)
va_list args;
va_start(args, data);
vwprintf(data, args);
va_end(args);
