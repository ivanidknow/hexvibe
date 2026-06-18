// Vulnerable: HFT-8617
void bad()
wchar_t * data;
data = NULL;
while(1)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
break;
size_t i;
...
data[100-1] = L'\0';
printWLine(data);
