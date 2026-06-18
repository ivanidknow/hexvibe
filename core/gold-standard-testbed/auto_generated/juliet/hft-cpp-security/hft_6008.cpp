// Vulnerable: HFT-6008
wchar_t * data;
CWE176_Improper_Handling_of_Unicode_Encoding__w32_67_structType myStruct;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
myStruct.structFirst = data;
CWE176_Improper_Handling_of_Unicode_Encoding__w32_67b_badSink(myStruct);
