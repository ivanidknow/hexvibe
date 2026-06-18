// Vulnerable: HFT-5687
void CWE134_Uncontrolled_Format_String__wchar_t_console_printf_64b_badSink(void * dataVoidPtr)
wchar_t * * dataPtr = (wchar_t * *)dataVoidPtr;
wchar_t * data = (*dataPtr);
wprintf(data);
