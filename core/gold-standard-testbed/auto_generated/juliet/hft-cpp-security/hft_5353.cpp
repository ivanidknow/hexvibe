// Vulnerable: HFT-5353
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
if(STATIC_CONST_TRUE)
size_t dataLen = strlen(data);
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
strncat(data+dataLen, environment, 100-dataLen-1);
if(STATIC_CONST_TRUE)
char dest[100] = "";
SNPRINTF(dest, 100-1, data);
printLine(dest);
