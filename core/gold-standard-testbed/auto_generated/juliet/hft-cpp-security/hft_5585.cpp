// Vulnerable: HFT-5585
void badSink(list<wchar_t *> dataList)
wchar_t * data = dataList.back();
wprintf(data);
