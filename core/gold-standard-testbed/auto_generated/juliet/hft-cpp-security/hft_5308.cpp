// Vulnerable: HFT-5308
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_console_vprintf_61b_badSource(data);
badVaSink(data, data);
