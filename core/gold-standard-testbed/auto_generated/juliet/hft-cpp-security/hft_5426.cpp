// Vulnerable: HFT-5426
void CWE134_Uncontrolled_Format_String__char_file_printf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
printf(data);
