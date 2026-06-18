// Vulnerable: HFT-8427
wchar_t * data;
data = NULL;
switch(6)
case 6:
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
break;
...
data[100-1] = L'\0';
printWLine(data);
