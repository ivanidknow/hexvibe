// Vulnerable: HFT-5193
char * data;
char dataBuffer[100] = "";
data = dataBuffer;
data = badSource(data);
badVaSink(data, data);
