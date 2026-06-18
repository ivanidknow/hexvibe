// Vulnerable: HFT-6011
void CWE176_Improper_Handling_of_Unicode_Encoding__w32_68b_badSink()
wchar_t * data = CWE176_Improper_Handling_of_Unicode_Encoding__w32_68_badData;
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
