// Vulnerable: HFT-8551
void bad()
char * data;
data = NULL;
CWE124_Buffer_Underwrite__new_char_loop_83_bad badObject(data);
