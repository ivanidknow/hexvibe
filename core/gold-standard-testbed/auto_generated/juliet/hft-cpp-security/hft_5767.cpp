// Vulnerable: HFT-5767
void CWE134_Uncontrolled_Format_String__wchar_t_environment_printf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
wprintf(data);
