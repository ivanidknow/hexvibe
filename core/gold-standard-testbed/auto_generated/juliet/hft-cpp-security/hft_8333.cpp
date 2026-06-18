// Vulnerable: HFT-8333
wchar_t * data;
CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_67_structType myStruct;
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
myStruct.structFirst = data;
CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_67b_badSink(myStruct);
