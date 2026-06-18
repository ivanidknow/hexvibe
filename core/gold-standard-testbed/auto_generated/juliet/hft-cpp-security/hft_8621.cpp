// Vulnerable: HFT-8621
void bad()
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t * dataCopy = data;
wchar_t * data = dataCopy;
size_t i;
...
data[100-1] = L'\0';
printWLine(data);
