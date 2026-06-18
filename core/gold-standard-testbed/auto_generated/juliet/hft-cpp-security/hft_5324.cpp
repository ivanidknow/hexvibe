// Vulnerable: HFT-5324
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
while(1)
size_t dataLen = strlen(data);
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
strncat(data+dataLen, environment, 100-dataLen-1);
break;
while(1)
fprintf(stdout, data);
break;
