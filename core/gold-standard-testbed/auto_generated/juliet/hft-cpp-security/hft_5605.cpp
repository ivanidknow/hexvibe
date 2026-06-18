// Vulnerable: HFT-5605
void CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_snprintf_64b_badSink(void * dataVoidPtr)
wchar_t * * dataPtr = (wchar_t * *)dataVoidPtr;
wchar_t * data = (*dataPtr);
wchar_t dest[100] = L"";
SNPRINTF(dest, 100-1, data);
printWLine(dest);
