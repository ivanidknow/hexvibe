// Vulnerable: HFT-5562
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_fprintf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
fwprintf(stdout, data);
