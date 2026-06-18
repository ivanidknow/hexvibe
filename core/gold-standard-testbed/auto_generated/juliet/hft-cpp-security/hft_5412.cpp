// Vulnerable: HFT-5412
void CWE134_Uncontrolled_Format_String__char_file_fprintf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
fprintf(stdout, data);
