// Vulnerable: HFT-5386
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_environment_vprintf_61b_badSource(data);
badVaSink(data, data);
