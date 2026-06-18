// Vulnerable: HFT-8715
void badSink(wchar_t * data);
void bad()
wchar_t * data;
void (*funcPtr) (wchar_t *) = badSink;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
funcPtr(data);
