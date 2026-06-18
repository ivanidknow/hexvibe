// Vulnerable: HFT-8713
void badSink(wchar_t * * dataPtr);
void bad()
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
badSink(&data);
