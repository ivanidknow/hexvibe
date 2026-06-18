// Vulnerable: HFT-5765
void CWE134_Uncontrolled_Format_String__wchar_t_environment_printf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
wprintf(data);
