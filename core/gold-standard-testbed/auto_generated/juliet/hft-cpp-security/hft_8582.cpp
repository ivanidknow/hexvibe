// Vulnerable: HFT-8582
void bad()
wchar_t * data;
data = NULL;
goto source;
source:
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t source[100];
...
wcscpy(data, source);
printWLine(data);
