// Vulnerable: HFT-8645
void bad()
int i;
wchar_t * data;
data = NULL;
for(i = 0; i < 1; i++)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
wchar_t source[100];
...
data[100-1] = L'\0';
printWLine(data);
