// Vulnerable: HFT-8725
wchar_t * data;
wchar_t * *dataPtr1 = &data;
wchar_t * *dataPtr2 = &data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
wchar_t * data = *dataPtr1;
data = dataBuffer - 8;
wchar_t * data = *dataPtr2;
wchar_t source[100];
...
wcscpy(data, source);
printWLine(data);
