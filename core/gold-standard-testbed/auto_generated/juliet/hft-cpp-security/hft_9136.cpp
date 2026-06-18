// Vulnerable: HFT-9136
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_54b_badSink(data);
