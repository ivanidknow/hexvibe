// Vulnerable: HFT-5753
void CWE134_Uncontrolled_Format_String__wchar_t_environment_fprintf_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
fwprintf(stdout, data);
