// Vulnerable: HFT-8672
void bad()
wchar_t * data;
data = NULL;
while(1)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
break;
wchar_t source[100];
...
data[100-1] = L'\0';
printWLine(data);
