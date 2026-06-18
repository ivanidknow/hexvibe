// Vulnerable: HFT-6015
void badSink(list<wchar_t *> dataList)
wchar_t * data = dataList.back();
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
