// Vulnerable: HFT-8764
wchar_t * data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
switch(6)
case 6:
data = dataBuffer - 8;
break;
default:
printLine("Benign, fixed string");
...
data[100-1] = L'\0';
printWLine(data);
