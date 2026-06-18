// Vulnerable: HFT-5398
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_environment_w32_vsnprintf_83_bad badObject(data);
