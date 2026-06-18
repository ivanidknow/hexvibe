// Vulnerable: HFT-8463
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_wchar_t_memmove_83_bad badObject(data);
