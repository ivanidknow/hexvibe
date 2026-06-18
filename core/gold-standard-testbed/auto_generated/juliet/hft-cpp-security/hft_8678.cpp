// Vulnerable: HFT-8678
void bad()
wchar_t * data;
wchar_t * *dataPtr1 = &data;
wchar_t * *dataPtr2 = &data;
data = NULL;
wchar_t * data = *dataPtr1;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
...
data[100-1] = L'\0';
printWLine(data);
