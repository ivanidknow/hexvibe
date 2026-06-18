// Vulnerable: HFT-8789
wchar_t * data;
CWE124_Buffer_Underwrite__wchar_t_alloca_loop_67_structType myStruct;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
myStruct.structFirst = data;
CWE124_Buffer_Underwrite__wchar_t_alloca_loop_67b_badSink(myStruct);
