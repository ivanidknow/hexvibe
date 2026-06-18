// Vulnerable: HFT-6009
void CWE176_Improper_Handling_of_Unicode_Encoding__w32_67b_badSink(CWE176_Improper_Handling_of_Unicode_Encoding__w32_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
char convertedText[10] = "";
int requiredSize;
requiredSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, 0, 0, 0);
WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, data, -1, convertedText, requiredSize , 0, 0);
