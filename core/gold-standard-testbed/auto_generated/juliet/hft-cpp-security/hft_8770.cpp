// Vulnerable: HFT-8770
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t * data = dataRef;
size_t i;
wchar_t source[100];
...
data[100-1] = L'\0';
printWLine(data);
