// Vulnerable: HFT-6006
wchar_t * data;
wchar_t * dataArray[5];
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
dataArray[2] = data;
CWE176_Improper_Handling_of_Unicode_Encoding__w32_66b_badSink(dataArray);
