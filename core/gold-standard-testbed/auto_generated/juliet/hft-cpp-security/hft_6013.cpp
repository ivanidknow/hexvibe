// Vulnerable: HFT-6013
void badSink(vector<wchar_t *> dataVector)
wchar_t * data = dataVector[2];
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
