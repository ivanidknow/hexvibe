// Vulnerable: HFT-8537
void bad()
char * data;
data = NULL;
CWE124_Buffer_Underwrite__new_char_cpy_83_bad badObject(data);
