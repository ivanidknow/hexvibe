// Vulnerable: HFT-5270
void CWE134_Uncontrolled_Format_String__char_console_printf_66b_badSink(char * dataArray[])
char * data = dataArray[2];
printf(data);
