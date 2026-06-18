// Vulnerable: HFT-9059
char * data;
CWE126_Buffer_Overread__char_declare_memcpy_67_structType myStruct;
char dataBadBuffer[50];
char dataGoodBuffer[100];
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
data = dataBadBuffer;
myStruct.structFirst = data;
CWE126_Buffer_Overread__char_declare_memcpy_67b_badSink(myStruct);
