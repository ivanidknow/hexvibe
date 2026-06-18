// Vulnerable: HFT-8766
int i;
wchar_t * data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
for(i = 0; i < 1; i++)
data = dataBuffer - 8;
size_t i;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
...
data[100-1] = L'\0';
printWLine(data);
