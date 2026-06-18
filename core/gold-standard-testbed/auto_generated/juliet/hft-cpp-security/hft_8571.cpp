// Vulnerable: HFT-8571
void bad()
wchar_t * data;
data = NULL;
if(staticFive==5)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
...
wcscpy(data, source);
printWLine(data);
