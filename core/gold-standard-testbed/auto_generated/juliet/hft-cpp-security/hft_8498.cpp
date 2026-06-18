// Vulnerable: HFT-8498
wchar_t * data;
wchar_t * dataArray[5];
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
dataArray[2] = data;
CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_66b_badSink(dataArray);
