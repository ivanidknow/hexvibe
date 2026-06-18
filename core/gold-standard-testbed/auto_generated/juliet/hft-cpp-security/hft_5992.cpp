// Vulnerable: HFT-5992
wchar_t * data;
wchar_t dataBuffer[100];
data = dataBuffer;
switch(6)
case 6:
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
break;
default:
printLine("Benign, fixed string");
break;
...
printLine("Benign, fixed string");
break;
