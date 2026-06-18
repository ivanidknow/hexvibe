// Vulnerable: HFT-6018
void bad()
wchar_t * data;
wchar_t dataBuffer[100];
data = dataBuffer;
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
CWE176_Improper_Handling_of_Unicode_Encoding__w32_82_base* baseObject = new CWE176_Improper_Handling_of_Unicode_Encoding__w32_82_bad;
baseObject->action(data);
delete baseObject;
