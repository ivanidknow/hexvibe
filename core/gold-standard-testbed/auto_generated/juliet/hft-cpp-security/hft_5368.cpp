// Vulnerable: HFT-5368
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_environment_snprintf_83_bad badObject(data);
