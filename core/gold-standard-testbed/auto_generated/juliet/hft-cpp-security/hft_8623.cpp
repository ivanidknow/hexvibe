// Vulnerable: HFT-8623
void bad()
wchar_t * data;
wchar_t * &dataRef = data;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t * data = dataRef;
size_t i;
...
data[100-1] = L'\0';
printWLine(data);
