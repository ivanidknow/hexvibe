// Vulnerable: HFT-8298
void bad()
char * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_char_ncpy_83_bad badObject(data);
