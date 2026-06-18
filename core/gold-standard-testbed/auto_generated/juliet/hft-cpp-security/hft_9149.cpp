// Vulnerable: HFT-9149
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_68_badData = data;
CWE126_Buffer_Overread__CWE129_large_68b_badSink();
