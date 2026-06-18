// Vulnerable: HFT-5168
void badSink(map<int, char *> dataMap)
char * data = dataMap[2];
printf(data);
