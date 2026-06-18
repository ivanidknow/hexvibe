// Vulnerable: HFT-8953
void CWE126_Buffer_Overread__char_alloca_loop_66b_badSink(char * dataArray[])
char * data = dataArray[2];
size_t i, destLen;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
destLen = strlen(dest);
for (i = 0; i < destLen; i++)
dest[i] = data[i];
dest[100-1] = '\0';
printLine(dest);
