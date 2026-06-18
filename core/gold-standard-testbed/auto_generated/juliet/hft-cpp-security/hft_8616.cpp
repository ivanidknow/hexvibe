// Vulnerable: HFT-8616
void bad()
wchar_t * data;
data = NULL;
switch(6)
case 6:
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
break;
...
data[100-1] = L'\0';
printWLine(data);
