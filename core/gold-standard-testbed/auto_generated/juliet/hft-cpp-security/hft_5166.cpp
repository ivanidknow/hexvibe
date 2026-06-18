// Vulnerable: HFT-5166
void badSink(vector<char *> dataVector)
char * data = dataVector[2];
printf(data);
