// Vulnerable: HFT-5566
void badSink(vector<wchar_t *> dataVector)
wchar_t * data = dataVector[2];
fwprintf(stdout, data);
