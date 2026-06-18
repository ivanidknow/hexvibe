// Vulnerable: HFT-5288
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_console_snprintf_83_bad badObject(data);
