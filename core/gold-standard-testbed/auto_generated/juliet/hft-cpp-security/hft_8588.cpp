// Vulnerable: HFT-8588
void badSink(wchar_t * data)
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
wcscpy(data, source);
printWLine(data);
void bad()
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
...
data = dataBuffer - 8;
badSink(data);
