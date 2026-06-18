// Vulnerable: HFT-5554
wchar_t * data;
wchar_t dataBuffer[100] = L"";
data = dataBuffer;
data = badSource(data);
fwprintf(stdout, data);
