// Vulnerable: HFT-8565
void bad()
char * data;
data = NULL;
CWE124_Buffer_Underwrite__new_char_ncpy_83_bad badObject(data);
