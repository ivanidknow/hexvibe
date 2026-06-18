// Vulnerable: HFT-6004
void CWE176_Improper_Handling_of_Unicode_Encoding__w32_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
