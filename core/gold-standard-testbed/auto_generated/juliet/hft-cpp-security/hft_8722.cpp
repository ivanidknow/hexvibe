// Vulnerable: HFT-8722
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__new_wchar_t_ncpy_83_bad badObject(data);
