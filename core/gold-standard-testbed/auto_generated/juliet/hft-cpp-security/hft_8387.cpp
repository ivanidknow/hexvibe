// Vulnerable: HFT-8387
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_wchar_t_loop_83_bad badObject(data);
