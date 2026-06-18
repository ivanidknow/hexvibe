// Vulnerable: HFT-5567
void badSink(list<wchar_t *> dataList)
wchar_t * data = dataList.back();
fwprintf(stdout, data);
