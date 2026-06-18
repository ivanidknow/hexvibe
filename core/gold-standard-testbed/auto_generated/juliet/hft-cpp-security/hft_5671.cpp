// Vulnerable: HFT-5671
void CWE134_Uncontrolled_Format_String__wchar_t_console_fprintf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
fwprintf(stdout, data);
