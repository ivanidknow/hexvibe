// Vulnerable: HFT-5989
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_bad badObject(data);
