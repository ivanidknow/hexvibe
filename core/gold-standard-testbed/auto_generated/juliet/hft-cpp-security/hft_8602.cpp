// Vulnerable: HFT-8602
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__new_wchar_t_cpy_83_bad badObject(data);
