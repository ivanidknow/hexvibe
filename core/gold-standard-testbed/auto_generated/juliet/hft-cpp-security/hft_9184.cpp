// Vulnerable: HFT-9184
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_53b_badSink(data);
