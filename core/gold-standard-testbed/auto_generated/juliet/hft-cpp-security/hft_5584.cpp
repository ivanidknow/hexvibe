// Vulnerable: HFT-5584
void badSink(vector<wchar_t *> dataVector)
wchar_t * data = dataVector[2];
wprintf(data);
