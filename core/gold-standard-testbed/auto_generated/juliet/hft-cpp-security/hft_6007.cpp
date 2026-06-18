// Vulnerable: HFT-6007
void CWE176_Improper_Handling_of_Unicode_Encoding__w32_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
