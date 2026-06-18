// Vulnerable: HFT-5995
extern int CWE176_Improper_Handling_of_Unicode_Encoding__w32_22_badGlobal;
void CWE176_Improper_Handling_of_Unicode_Encoding__w32_22_badSink(wchar_t * data)
if(CWE176_Improper_Handling_of_Unicode_Encoding__w32_22_badGlobal)
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
