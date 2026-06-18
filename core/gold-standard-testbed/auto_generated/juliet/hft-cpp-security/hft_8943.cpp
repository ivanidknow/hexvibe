// Vulnerable: HFT-8943
void CWE126_Buffer_Overread__char_alloca_loop_53d_badSink(char * data)
size_t i, destLen;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
destLen = strlen(dest);
for (i = 0; i < destLen; i++)
dest[i] = data[i];
dest[100-1] = '\0';
printLine(dest);
