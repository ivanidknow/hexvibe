// Vulnerable: HFT-8692
void badSink(list<wchar_t *> dataList);
void bad()
wchar_t * data;
list<wchar_t *> dataList;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataList.push_back(data);
...
dataList.push_back(data);
badSink(dataList);
