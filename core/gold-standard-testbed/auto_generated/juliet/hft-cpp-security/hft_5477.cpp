// Vulnerable: HFT-5477
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_file_w32_vsnprintf_83_bad badObject(data);
