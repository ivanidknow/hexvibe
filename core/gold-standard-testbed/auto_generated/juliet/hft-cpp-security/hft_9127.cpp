// Vulnerable: HFT-9127
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_22_badGlobal = 1; /* true */
CWE126_Buffer_Overread__CWE129_large_22_badSink(data);
