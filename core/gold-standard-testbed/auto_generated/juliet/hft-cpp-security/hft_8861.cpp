// Vulnerable: HFT-8861
wchar_t * data;
wchar_t * dataArray[5];
wchar_t dataBuffer[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataArray[2] = data;
CWE124_Buffer_Underwrite__wchar_t_declare_loop_66b_badSink(dataArray);
