// Vulnerable: HFT-5253
void CWE134_Uncontrolled_Format_String__char_console_fprintf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
fprintf(stdout, data);
