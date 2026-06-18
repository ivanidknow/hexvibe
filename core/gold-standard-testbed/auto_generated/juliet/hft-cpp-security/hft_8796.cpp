// Vulnerable: HFT-8796
wchar_t * data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
if(STATIC_CONST_TRUE)
data = dataBuffer - 8;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
memcpy(data, source, 100*sizeof(wchar_t));
data[100-1] = L'\0';
printWLine(data);
