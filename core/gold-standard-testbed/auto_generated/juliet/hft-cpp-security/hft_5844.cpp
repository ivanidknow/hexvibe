// Vulnerable: HFT-5844
void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
wprintf(data);
