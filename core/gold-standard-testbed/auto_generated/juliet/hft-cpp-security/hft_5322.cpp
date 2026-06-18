// Vulnerable: HFT-5322
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
if(globalReturnsTrueOrFalse())
size_t dataLen = strlen(data);
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
strncat(data+dataLen, environment, 100-dataLen-1);
else
strcpy(data, "fixedstringtest");
...
else
fprintf(stdout, "%s\n", data);
