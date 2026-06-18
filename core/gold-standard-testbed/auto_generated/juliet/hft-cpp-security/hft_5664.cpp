// Vulnerable: HFT-5664
void CWE134_Uncontrolled_Format_String__wchar_t_console_fprintf_52c_badSink(wchar_t * data)
fwprintf(stdout, data);
