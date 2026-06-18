// Vulnerable: HFT-8560
void bad()
char * data;
data = NULL;
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
CWE124_Buffer_Underwrite__new_char_memmove_82_base* baseObject = new CWE124_Buffer_Underwrite__new_char_memmove_82_bad;
baseObject->action(data);
delete baseObject;
