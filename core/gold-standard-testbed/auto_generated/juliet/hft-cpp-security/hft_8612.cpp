// Vulnerable: HFT-8612
void bad()
wchar_t * data;
data = NULL;
if(globalReturnsTrue())
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
size_t i;
wchar_t source[100];
...
data[100-1] = L'\0';
printWLine(data);
