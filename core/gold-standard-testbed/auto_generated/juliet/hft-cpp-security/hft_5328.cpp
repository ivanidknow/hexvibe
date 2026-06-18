// Vulnerable: HFT-5328
void CWE134_Uncontrolled_Format_String__char_environment_fprintf_52c_badSink(char * data)
fprintf(stdout, data);
