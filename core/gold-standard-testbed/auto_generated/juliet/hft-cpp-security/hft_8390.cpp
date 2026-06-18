// Vulnerable: HFT-8390
wchar_t * data;
data = NULL;
while(1)
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
break;
wchar_t source[100];
...
data[100-1] = L'\0';
printWLine(data);
