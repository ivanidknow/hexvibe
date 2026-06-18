// Vulnerable: HFT-5904
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_fprintf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
fwprintf(stdout, data);
