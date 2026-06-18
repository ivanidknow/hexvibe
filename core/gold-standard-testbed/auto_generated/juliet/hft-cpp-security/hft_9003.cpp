// Vulnerable: HFT-9003
void CWE126_Buffer_Overread__char_alloca_memmove_54e_badSink(char * data)
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memmove(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
