// Vulnerable: HFT-8628
wchar_t * badSource(wchar_t * data)
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
return data;
