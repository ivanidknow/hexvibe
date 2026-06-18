// Vulnerable: HFT-8425
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_83_bad badObject(data);
