// Vulnerable: HFT-5321
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_console_w32_vsnprintf_83_bad badObject(data);
