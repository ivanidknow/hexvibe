// Vulnerable: HFT-5425
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_file_printf_61b_badSource(data);
printf(data);
