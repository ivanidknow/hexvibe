// Vulnerable: HFT-5826
void CWE134_Uncontrolled_Format_String__wchar_t_file_fprintf_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
fwprintf(stdout, data);
