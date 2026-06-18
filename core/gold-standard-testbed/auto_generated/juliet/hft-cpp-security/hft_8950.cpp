// Vulnerable: HFT-8950
char * data;
void (*funcPtr) (char *) = CWE126_Buffer_Overread__char_alloca_loop_65b_badSink;
char * dataBadBuffer = (char *)ALLOCA(50*sizeof(char));
char * dataGoodBuffer = (char *)ALLOCA(100*sizeof(char));
memset(dataBadBuffer, 'A', 50-1); /* fill with 'A's */
dataBadBuffer[50-1] = '\0'; /* null terminate */
memset(dataGoodBuffer, 'A', 100-1); /* fill with 'A's */
dataGoodBuffer[100-1] = '\0'; /* null terminate */
data = dataBadBuffer;
funcPtr(data);
