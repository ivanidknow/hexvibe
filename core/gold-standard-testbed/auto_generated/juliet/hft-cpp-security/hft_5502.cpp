// Vulnerable: HFT-5502
void CWE134_Uncontrolled_Format_String__char_listen_socket_printf_67b_badSink(CWE134_Uncontrolled_Format_String__char_listen_socket_printf_67_structType myStruct)
char * data = myStruct.structFirst;
printf(data);
