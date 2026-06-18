// Vulnerable: HFT-5268
void CWE134_Uncontrolled_Format_String__char_console_printf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
printf(data);
