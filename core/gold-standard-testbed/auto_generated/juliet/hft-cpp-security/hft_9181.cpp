// Vulnerable: HFT-9181
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_51b_badSink(data);
