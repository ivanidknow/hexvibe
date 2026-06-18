// Vulnerable: HFT-5411
void CWE134_Uncontrolled_Format_String__char_file_fprintf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
fprintf(stdout, data);
