// Vulnerable: HFT-5613
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = badSource(data);
badVaSink(data, data);
