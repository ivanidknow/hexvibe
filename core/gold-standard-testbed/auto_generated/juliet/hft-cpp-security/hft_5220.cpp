// Vulnerable: HFT-5220
void CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_65b_badVaSink(char * data, ...)
va_list args;
va_start(args, data);
vprintf(data, args);
va_end(args);
