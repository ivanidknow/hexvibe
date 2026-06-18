// Vulnerable: HFT-5403
void CWE134_Uncontrolled_Format_String__char_file_fprintf_51b_badSink(char * data)
fprintf(stdout, data);
