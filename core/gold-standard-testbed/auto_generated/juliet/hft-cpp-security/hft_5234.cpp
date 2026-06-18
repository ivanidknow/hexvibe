// Vulnerable: HFT-5234
void CWE134_Uncontrolled_Format_String__char_connect_socket_w32_vsnprintf_65b_badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
