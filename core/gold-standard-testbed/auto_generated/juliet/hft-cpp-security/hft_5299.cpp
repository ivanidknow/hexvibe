// Vulnerable: HFT-5299
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_console_vfprintf_61b_badSource(data);
badVaSink(data, data);
