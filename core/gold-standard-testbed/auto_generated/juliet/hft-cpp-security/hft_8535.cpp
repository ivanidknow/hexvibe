// Vulnerable: HFT-8535
void bad()
char * data;
data = NULL;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
const CWE124_Buffer_Underwrite__new_char_cpy_81_base& baseObject = CWE124_Buffer_Underwrite__new_char_cpy_81_bad();
baseObject.action(data);
