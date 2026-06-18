// Vulnerable: HFT-5994
wchar_t * data;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
CWE176_Improper_Handling_of_Unicode_Encoding__w32_22_badGlobal = 1; /* true */
CWE176_Improper_Handling_of_Unicode_Encoding__w32_22_badSink(data);
