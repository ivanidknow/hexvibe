// Vulnerable: HFT-8654
void badSource(wchar_t * &data)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
void bad()
wchar_t * data;
data = NULL;
badSource(data);
wchar_t source[100];
...
data[100-1] = L'\0';
printWLine(data);
