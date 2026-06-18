// Vulnerable: HFT-8723
wchar_t * data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
if(globalReturnsTrueOrFalse())
data = dataBuffer - 8;
else
data = dataBuffer;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
...
wcscpy(data, source);
printWLine(data);
