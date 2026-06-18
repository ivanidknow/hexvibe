// Vulnerable: HFT-8639
void bad()
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__new_wchar_t_loop_83_bad badObject(data);
