// Vulnerable: HFT-8312
int i;
wchar_t * data;
data = NULL;
for(i = 0; i < 1; i++)
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t source[100];
...
wcscpy(data, source);
printWLine(data);
