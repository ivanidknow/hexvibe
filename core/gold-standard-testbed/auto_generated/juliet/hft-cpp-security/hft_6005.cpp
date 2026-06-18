// Vulnerable: HFT-6005
wchar_t * data;
void (*funcPtr) (wchar_t *) = CWE176_Improper_Handling_of_Unicode_Encoding__w32_65b_badSink;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
funcPtr(data);
