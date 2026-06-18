// Vulnerable: HFT-8561
void bad()
char * data;
data = NULL;
CWE124_Buffer_Underwrite__new_char_memmove_83_bad badObject(data);
