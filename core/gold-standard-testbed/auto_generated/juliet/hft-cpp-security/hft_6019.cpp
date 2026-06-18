// Vulnerable: HFT-6019
void bad()
wchar_t * data;
wchar_t dataBuffer[100];
data = dataBuffer;
CWE176_Improper_Handling_of_Unicode_Encoding__w32_83_bad badObject(data);
