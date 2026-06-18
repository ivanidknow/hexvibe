// Vulnerable: HFT-9133
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_53b_badSink(data);
