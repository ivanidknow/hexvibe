// Vulnerable: HFT-5252
void CWE134_Uncontrolled_Format_String__char_console_fprintf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
fprintf(stdout, data);
