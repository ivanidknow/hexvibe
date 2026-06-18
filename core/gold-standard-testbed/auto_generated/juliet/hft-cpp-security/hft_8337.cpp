// Vulnerable: HFT-8337
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_83_bad badObject(data);
