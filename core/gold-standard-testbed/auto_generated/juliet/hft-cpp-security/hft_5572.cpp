// Vulnerable: HFT-5572
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = badSource(data);
wprintf(data);
