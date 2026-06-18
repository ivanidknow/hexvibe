// Vulnerable: HFT-8792
void badSink(list<wchar_t *> dataList);
void bad()
wchar_t * data;
list<wchar_t *> dataList;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataList.push_back(data);
dataList.push_back(data);
dataList.push_back(data);
badSink(dataList);
