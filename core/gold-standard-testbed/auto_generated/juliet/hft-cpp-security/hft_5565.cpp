// Vulnerable: HFT-5565
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_fprintf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_fprintf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
fwprintf(stdout, data);
