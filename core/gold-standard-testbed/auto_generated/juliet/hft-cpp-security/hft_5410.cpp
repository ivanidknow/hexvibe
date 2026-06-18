// Vulnerable: HFT-5410
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = CWE134_Uncontrolled_Format_String__char_file_fprintf_61b_badSource(data);
fprintf(stdout, data);
