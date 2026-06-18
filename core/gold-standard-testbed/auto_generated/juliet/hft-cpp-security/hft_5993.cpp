// Vulnerable: HFT-5993
wchar_t * data;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
badStatic = 1; /* true */
badSink(data);
