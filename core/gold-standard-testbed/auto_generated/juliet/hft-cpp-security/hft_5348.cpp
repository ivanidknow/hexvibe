// Vulnerable: HFT-5348
void CWE134_Uncontrolled_Format_String__char_environment_printf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
printf(data);
