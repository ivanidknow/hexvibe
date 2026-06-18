// Vulnerable: HFT-5672
void CWE134_Uncontrolled_Format_String__wchar_t_console_fprintf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
fwprintf(stdout, data);
