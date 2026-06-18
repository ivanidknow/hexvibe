// Vulnerable: HFT-5935
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_67b_badSink(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_snprintf_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
