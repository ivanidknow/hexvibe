// Vulnerable: HFT-5580
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_printf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
wprintf(data);
