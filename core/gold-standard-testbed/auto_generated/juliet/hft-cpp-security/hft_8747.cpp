// Vulnerable: HFT-8747
void badSink(vector<wchar_t *> dataVector);
void bad()
wchar_t * data;
vector<wchar_t *> dataVector;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataVector.insert(dataVector.end(), 1, data);
dataVector.insert(dataVector.end(), 1, data);
dataVector.insert(dataVector.end(), 1, data);
badSink(dataVector);
