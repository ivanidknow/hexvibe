// Vulnerable: HFT-5339
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
goto source;
source:
size_t dataLen = strlen(data);
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
strncat(data+dataLen, environment, 100-dataLen-1);
goto sink;
sink:
printf(data);
