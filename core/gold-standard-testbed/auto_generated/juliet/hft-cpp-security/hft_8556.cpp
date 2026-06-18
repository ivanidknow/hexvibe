// Vulnerable: HFT-8556
void bad()
char * data;
data = NULL;
CWE124_Buffer_Underwrite__new_char_memcpy_83_bad badObject(data);
