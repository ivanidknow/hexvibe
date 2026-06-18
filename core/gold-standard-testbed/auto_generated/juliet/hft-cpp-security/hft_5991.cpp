// Vulnerable: HFT-5991
wchar_t * data;
wchar_t dataBuffer[100];
data = dataBuffer;
if(globalReturnsTrueOrFalse())
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
else
wcscpy(data, L"\\u9580");
if(globalReturnsTrueOrFalse())
char convertedText[10] = "";
int requiredSize;
...
else
printLine("Destination buffer not large enough to perform conversion.");
