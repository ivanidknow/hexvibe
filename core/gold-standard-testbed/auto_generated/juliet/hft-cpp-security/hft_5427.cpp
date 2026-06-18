// Vulnerable: HFT-5427
void CWE134_Uncontrolled_Format_String__char_file_printf_64b_badSink(void * dataVoidPtr)
char * * dataPtr = (char * *)dataVoidPtr;
char * data = (*dataPtr);
printf(data);
