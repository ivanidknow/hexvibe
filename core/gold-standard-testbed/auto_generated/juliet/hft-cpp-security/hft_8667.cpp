// Vulnerable: HFT-8667
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__new_wchar_t_memcpy_83_bad badObject(data);
