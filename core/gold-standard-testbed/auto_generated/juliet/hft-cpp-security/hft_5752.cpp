// Vulnerable: HFT-5752
void CWE134_Uncontrolled_Format_String__wchar_t_environment_fprintf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
fwprintf(stdout, data);
