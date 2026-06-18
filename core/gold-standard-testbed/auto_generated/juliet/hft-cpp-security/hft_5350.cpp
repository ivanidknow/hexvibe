// Vulnerable: HFT-5350
void CWE134_Uncontrolled_Format_String__char_environment_printf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
printf(data);
