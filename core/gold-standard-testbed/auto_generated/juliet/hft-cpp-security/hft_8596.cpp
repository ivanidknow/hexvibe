// Vulnerable: HFT-8596
void badSink(wchar_t * dataArray[]);
void bad()
wchar_t * data;
wchar_t * dataArray[5];
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataArray[2] = data;
badSink(dataArray);
