// Vulnerable: HFT-9060
void bad()
char * data;
char dataBadBuffer[50];
char dataGoodBuffer[100];
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
data = dataBadBuffer;
const CWE126_Buffer_Overread__char_declare_memcpy_81_base& baseObject = CWE126_Buffer_Overread__char_declare_memcpy_81_bad();
baseObject.action(data);
