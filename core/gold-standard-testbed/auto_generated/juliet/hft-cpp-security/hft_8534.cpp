// Vulnerable: HFT-8534
void badSink();
void bad()
char * data;
data = NULL;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
CWE124_Buffer_Underwrite__new_char_cpy_68_badData = data;
badSink();
