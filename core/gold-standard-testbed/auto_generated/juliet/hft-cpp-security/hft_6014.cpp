// Vulnerable: HFT-6014
void badSink(list<wchar_t *> dataList);
void bad()
wchar_t * data;
list<wchar_t *> dataList;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
dataList.push_back(data);
dataList.push_back(data);
dataList.push_back(data);
badSink(dataList);
