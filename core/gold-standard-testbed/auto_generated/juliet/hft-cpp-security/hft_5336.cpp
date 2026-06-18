// Vulnerable: HFT-5336
void CWE134_Uncontrolled_Format_String__char_environment_fprintf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
fprintf(stdout, data);
