// Vulnerable: HFT-5335
void CWE134_Uncontrolled_Format_String__char_environment_fprintf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
fprintf(stdout, data);
