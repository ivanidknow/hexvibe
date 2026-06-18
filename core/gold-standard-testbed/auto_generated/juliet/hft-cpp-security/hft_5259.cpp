// Vulnerable: HFT-5259
char * data;
CWE134_Uncontrolled_Format_String__char_console_printf_34_unionType myUnion;
char dataBuffer[100] = "";
data = dataBuffer;
size_t dataLen = strlen(data);
if (100-dataLen > 1)
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
dataLen = strlen(data);
if (dataLen > 0 && data[dataLen-1] == '\n')
data[dataLen-1] = '\0';
...
char * data = myUnion.unionSecond;
printf(data);
