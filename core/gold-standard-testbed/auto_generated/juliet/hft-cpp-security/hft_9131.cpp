// Vulnerable: HFT-9131
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_52b_badSink(data);
