// Vulnerable: HFT-8310
wchar_t * data;
data = NULL;
if(globalFive==5)
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
...
wcscpy(data, source);
printWLine(data);
