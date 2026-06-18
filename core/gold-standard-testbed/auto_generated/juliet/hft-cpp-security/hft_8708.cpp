// Vulnerable: HFT-8708
void bad()
wchar_t * data;
unionType myUnion;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
myUnion.unionFirst = data;
wchar_t * data = myUnion.unionSecond;
...
data[100-1] = L'\0';
printWLine(data);
