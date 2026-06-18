// Vulnerable: HFT-5487
void CWE134_Uncontrolled_Format_String__char_listen_socket_fprintf_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
fprintf(stdout, data);
