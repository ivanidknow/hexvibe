// Vulnerable: HFT-9129
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_45_badData = data;
badSink();
