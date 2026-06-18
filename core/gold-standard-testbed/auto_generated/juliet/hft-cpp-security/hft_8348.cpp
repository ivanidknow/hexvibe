// Vulnerable: HFT-8348
wchar_t * data;
data = NULL;
if(globalReturnsTrueOrFalse())
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
else
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
...
data[100-1] = L'\0';
printWLine(data);
