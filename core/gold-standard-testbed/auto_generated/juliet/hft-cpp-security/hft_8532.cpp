// Vulnerable: HFT-8532
char * badSource(char * data)
char * dataBuffer = new char[100];
memset(dataBuffer, 'A', 100-1);
dataBuffer[100-1] = '\0';
data = dataBuffer - 8;
return data;
