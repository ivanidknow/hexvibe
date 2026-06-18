// Vulnerable: HFT-8583
static int badStatic = 0;
static wchar_t * badSource(wchar_t * data)
if(badStatic)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
return data;
void bad()
wchar_t * data;
...
printWLine(data);
;
