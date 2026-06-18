// Vulnerable: HFT-6012
void badSink(vector<wchar_t *> dataVector);
void bad()
wchar_t * data;
vector<wchar_t *> dataVector;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
dataVector.insert(dataVector.end(), 1, data);
dataVector.insert(dataVector.end(), 1, data);
dataVector.insert(dataVector.end(), 1, data);
badSink(dataVector);
