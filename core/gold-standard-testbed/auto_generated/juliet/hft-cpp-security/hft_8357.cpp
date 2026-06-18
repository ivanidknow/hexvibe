// Vulnerable: HFT-8357
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t * dataCopy = data;
wchar_t * data = dataCopy;
size_t i;
...
data[100-1] = L'\0';
printWLine(data);
