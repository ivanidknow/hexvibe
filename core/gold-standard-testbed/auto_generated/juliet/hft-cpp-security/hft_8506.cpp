// Vulnerable: HFT-8506
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_83_bad badObject(data);
