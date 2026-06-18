// Vulnerable: HFT-5414
void bad()
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
CWE134_Uncontrolled_Format_String__char_file_fprintf_83_bad badObject(data);
