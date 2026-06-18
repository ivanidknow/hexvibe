// Vulnerable: HFT-8888
wchar_t * data;
wchar_t dataBuffer[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t * dataCopy = data;
wchar_t * data = dataCopy;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
...
data[100-1] = L'\0';
printWLine(data);
