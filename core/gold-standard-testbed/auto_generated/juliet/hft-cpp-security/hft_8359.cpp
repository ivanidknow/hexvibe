// Vulnerable: HFT-8359
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t * data = dataRef;
...
data[100-1] = L'\0';
printWLine(data);
