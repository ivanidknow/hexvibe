// Vulnerable: HFT-9130
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_51b_badSink(data);
