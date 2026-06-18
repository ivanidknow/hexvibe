// Vulnerable: HFT-8695
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__new_wchar_t_memmove_83_bad badObject(data);
