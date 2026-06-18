// Vulnerable: HFT-5167
void badSink(list<char *> dataList)
char * data = dataList.back();
printf(data);
